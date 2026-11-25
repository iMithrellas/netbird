package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/store"
	sharedgrpc "github.com/netbirdio/netbird/shared/management/grpc"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/peerauth"
)

func TestExternalFlowEncryptedSync(t *testing.T) {
	const accountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b" // store_with_expired_peers.sql
	const collectorURL = "https://collector.example.org:443"
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pem, err := peerauth.MarshalSigningKeyPEM(key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "flow.pem")
	require.NoError(t, os.WriteFile(path, pem, 0600))
	t.Setenv("NB_EXTERNAL_FLOW_ENABLED", "true")
	t.Setenv("NB_EXTERNAL_FLOW_ACCOUNT_ID", accountID)
	t.Setenv("NB_EXTERNAL_FLOW_URL", collectorURL)
	t.Setenv("NB_EXTERNAL_FLOW_AUDIENCE", "local-collector")
	t.Setenv("NB_EXTERNAL_FLOW_SIGNING_KEY_FILE", path)
	t.Setenv("NB_EXTERNAL_FLOW_INTERVAL", "5s")

	s, am, addr, cleanup, err := startManagementForTest(t, "testdata/store_with_expired_peers.sql", &config.Config{
		Datadir: t.TempDir(),
		Signal:  &config.Host{Proto: config.HTTPS, URI: "signal.example.org:443"},
	})
	require.NoError(t, err)
	t.Cleanup(cleanup)
	t.Cleanup(s.GracefulStop)
	client, conn, err := createRawClient(addr)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	serverKey, err := getServerKey(client)
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		version sharedgrpc.SyncMessageVersion
	}{{"legacy", sharedgrpc.Base}, {"components", sharedgrpc.ComponentNetworkMap}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			peerKey, err := wgtypes.GeneratePrivateKey()
			require.NoError(t, err)
			_, err = loginPeerWithValidSetupKey(peerKey, client)
			require.NoError(t, err)
			peer, err := am.GetStore().GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, peerKey.PublicKey().String())
			require.NoError(t, err)
			body, err := encryption.EncryptMessage(*serverKey, peerKey, &proto.SyncRequest{
				Meta: &proto.PeerSystemMeta{Hostname: "flow-" + tc.name, GoOS: "linux", SyncMessageVersion: int32(tc.version)},
			})
			require.NoError(t, err)
			stream, err := client.Sync(ctx, &proto.EncryptedMessage{WgPubKey: peerKey.PublicKey().String(), Body: body})
			require.NoError(t, err)
			msg, err := stream.Recv()
			require.NoError(t, err)
			resp := new(proto.SyncResponse)
			require.NoError(t, encryption.DecryptMessage(*serverKey, peerKey, msg.Body, resp))
			assert.Equal(t, tc.version == sharedgrpc.ComponentNetworkMap, resp.NetworkMapEnvelope != nil, "negotiated map format")
			assert.Equal(t, "signal.example.org:443", resp.GetNetbirdConfig().GetSignal().GetUri(), "global config must still carry Signal")

			flow := resp.GetNetbirdConfig().GetFlow()
			require.True(t, flow.GetEnabled(), "peer must receive an enabled collector")
			assert.Equal(t, collectorURL, flow.Url, "collector address")
			assert.Equal(t, 5*time.Second, flow.Interval.AsDuration(), "reporting interval")
			sig, err := base64.RawURLEncoding.DecodeString(flow.TokenSignature)
			require.NoError(t, err)
			require.True(t, ed25519.Verify(pub, []byte(flow.TokenPayload), sig), "signature must authenticate the encoded payload")
			payload, err := base64.RawURLEncoding.DecodeString(flow.TokenPayload)
			require.NoError(t, err)
			var claims struct {
				Version int    `json:"v"`
				Aud     string `json:"aud"`
				Exp     int64  `json:"exp"`
				Account string `json:"account_id"`
				Peer    string `json:"peer_id"`
				Key     string `json:"wg_pub_key"`
			}
			require.NoError(t, json.Unmarshal(payload, &claims))
			assert.Equal(t, 1, claims.Version, "token format")
			assert.Equal(t, "local-collector", claims.Aud, "recipient")
			assert.WithinDuration(t, time.Now().Add(time.Hour), time.Unix(claims.Exp, 0), 5*time.Second, "credential lifetime")
			assert.Equal(t, peer.AccountID, claims.Account, "authenticated account")
			assert.Equal(t, peer.ID, claims.Peer, "authenticated peer")
			assert.Equal(t, peerKey.PublicKey().String(), claims.Key, "reporting key")
		})
	}
}
