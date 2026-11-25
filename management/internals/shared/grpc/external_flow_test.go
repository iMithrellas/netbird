package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/peerauth"
)

func TestExternalFlowScopeAndDisable(t *testing.T) {
	peer := &nbpeer.Peer{AccountID: "poc", ID: "peer"}
	key := mustGenerateKey(t).PublicKey()
	t.Setenv(envExternalFlowEnabled, "")
	require.NoError(t, os.Unsetenv(envExternalFlowEnabled))
	cfg, err := loadExternalFlowConfig()
	require.NoError(t, err)
	existing := &proto.FlowConfig{Enabled: true, Url: "https://existing.example:443"}
	global := &proto.NetbirdConfig{Flow: existing}
	require.NoError(t, cfg.forPeer(peer, key).apply(global))
	assert.Same(t, existing, global.Flow, "unconfigured deployment must preserve upstream flow")

	t.Setenv(envExternalFlowEnabled, "false")
	t.Setenv(envExternalFlowAccount, "another-account")
	cfg, err = loadExternalFlowConfig()
	require.NoError(t, err)
	require.NoError(t, cfg.forPeer(peer, key).apply(global))
	assert.Same(t, existing, global.Flow, "other accounts must keep their own settings")

	t.Setenv(envExternalFlowAccount, peer.AccountID)
	cfg, err = loadExternalFlowConfig()
	require.NoError(t, err)
	s := cfg.forPeer(peer, key)
	require.NoError(t, s.apply(global))
	require.NotNil(t, global.Flow, "disable must reach a peer with a running sender")
	assert.False(t, global.Flow.Enabled, "a previously enabled sender must stop")
	assert.Positive(t, global.Flow.Interval.AsDuration(), "stock clients require an interval even when disabling")
	assert.Empty(t, global.Flow.TokenPayload, "no token is issued when disabled")
}

func TestExternalFlowRejectsInvalidConfig(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pem, err := peerauth.MarshalSigningKeyPEM(key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "flow.key")
	require.NoError(t, os.WriteFile(path, pem, 0600))
	t.Setenv(envExternalFlowEnabled, "true")
	t.Setenv(envExternalFlowAccount, "poc")
	t.Setenv(envExternalFlowURL, "https://[::1]:8443")
	t.Setenv(envExternalFlowAudience, "poc")
	t.Setenv(envExternalFlowInterval, "5s")
	t.Setenv(envExternalFlowKeyFile, path)
	_, err = loadExternalFlowConfig()
	require.NoError(t, err)

	for _, tc := range []struct{ name, variable, value string }{
		{"explicit enable", envExternalFlowEnabled, "maybe"},
		{"account required", envExternalFlowAccount, ""},
		{"cleartext", envExternalFlowURL, "http://collector:8443"},
		{"userinfo", envExternalFlowURL, "https://user@collector:8443"},
		{"path", envExternalFlowURL, "https://collector:8443/ingest"},
		{"query", envExternalFlowURL, "https://collector:8443/?token=secret"},
		{"port", envExternalFlowURL, "https://collector:65536"},
		{"audience", envExternalFlowAudience, " "},
		{"nil ticker", envExternalFlowInterval, "0s"},
		{"never flush", envExternalFlowInterval, "1h"},
		{"missing key", envExternalFlowKeyFile, path + ".missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.variable, tc.value)
			_, err := loadExternalFlowConfig()
			require.ErrorContains(t, err, tc.variable)
		})
	}
}

type flowTestStream struct {
	ctx  context.Context
	sent chan *proto.EncryptedMessage
}

func (s flowTestStream) Context() context.Context { return s.ctx }
func (s flowTestStream) Send(msg *proto.EncryptedMessage) error {
	s.sent <- msg
	return nil
}

func TestExternalFlowRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		secrets, err := NewTimeBasedAuthSecretsManager(nil, nil, nil, nil, nil)
		require.NoError(t, err)
		serverKey, err := secrets.GetWGKey()
		require.NoError(t, err)
		peerKey := mustGenerateKey(t)
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		cfg := &externalFlowConfig{account: "poc", url: "https://collector:8443", audience: "poc", key: priv, interval: time.Minute}
		f := cfg.forPeer(&nbpeer.Peer{AccountID: "poc", ID: "peer"}, peerKey.PublicKey())
		initial := &proto.NetbirdConfig{Relay: &proto.RelayConfig{Urls: []string{"rels://old:443"}}}
		require.NoError(t, f.apply(initial))
		f.observe(initial)

		stream := flowTestStream{ctx: ctx, sent: make(chan *proto.EncryptedMessage, 1)}
		updates := make(chan *network_map.UpdateMessage)
		handler := &PeerUpdateHandler{
			peerKey: peerKey.PublicKey(), flow: f, updates: updates, secretsManager: secrets,
			srv: stream, encrypter: encryption.DefaultEncrypter{}, debouncer: NewUpdateDebouncer(time.Second), cleanupFunc: func() {},
		}
		done := make(chan error, 1)
		go func() { done <- handler.HandleUpdates(ctx) }()
		// Credential rotation followed by a map-only update must survive the flow refresh.
		rotated := &proto.NetbirdConfig{Relay: &proto.RelayConfig{Urls: []string{"rels://new:443"}}, AuthToken: []byte("rotated")}
		for _, cfg := range []*proto.NetbirdConfig{rotated, nil} {
			updates <- &network_map.UpdateMessage{Update: &proto.SyncResponse{NetbirdConfig: cfg}}
			<-stream.sent
		}
		msg := <-stream.sent // fake time advances to the flow refresh without TURN or Relay timers
		resp := new(proto.SyncResponse)
		require.NoError(t, encryption.DecryptMessage(serverKey.PublicKey(), peerKey, msg.Body, resp))
		got := resp.GetNetbirdConfig()
		require.NotNil(t, got.GetFlow(), "refresh must include a new credential")
		assert.Equal(t, rotated.Relay.Urls, got.GetRelay().GetUrls(), "retain live relay URLs")
		assert.Equal(t, rotated.AuthToken, got.AuthToken, "retain live Signal and Relay authentication")
		assert.NotEqual(t, initial.Flow.TokenPayload, got.Flow.TokenPayload, "credential must rotate")
		sig, err := base64.RawURLEncoding.DecodeString(got.Flow.TokenSignature)
		require.NoError(t, err)
		assert.True(t, ed25519.Verify(pub, []byte(got.Flow.TokenPayload), sig), "renewed token must verify")
		raw, err := base64.RawURLEncoding.DecodeString(got.Flow.TokenPayload)
		require.NoError(t, err)
		var claims flowClaims
		require.NoError(t, json.Unmarshal(raw, &claims))
		assert.Equal(t, time.Now().Add(externalFlowTokenTTL).Unix(), claims.ExpiresAt, "new token extends expiry")
		close(updates)
		require.NoError(t, <-done)
	})
}
