package grpc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	pb "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/peerauth"
)

const (
	envExternalFlowEnabled  = "NB_EXTERNAL_FLOW_ENABLED"
	envExternalFlowAccount  = "NB_EXTERNAL_FLOW_ACCOUNT_ID"
	envExternalFlowURL      = "NB_EXTERNAL_FLOW_URL"
	envExternalFlowAudience = "NB_EXTERNAL_FLOW_AUDIENCE"
	envExternalFlowKeyFile  = "NB_EXTERNAL_FLOW_SIGNING_KEY_FILE"
	envExternalFlowInterval = "NB_EXTERNAL_FLOW_INTERVAL"

	externalFlowTokenTTL = time.Hour
)

type flowAccountID string
type flowPeerID string

type externalFlowConfig struct {
	account  flowAccountID
	url      string
	audience string
	key      ed25519.PrivateKey
	interval time.Duration
}

func loadExternalFlowConfig() (externalFlowConfig, error) {
	var cfg externalFlowConfig
	raw, set := os.LookupEnv(envExternalFlowEnabled)
	if !set {
		return cfg, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return cfg, fmt.Errorf("%s: %w", envExternalFlowEnabled, err)
	}
	cfg.account = flowAccountID(strings.TrimSpace(os.Getenv(envExternalFlowAccount)))
	if cfg.account == "" {
		return cfg, fmt.Errorf("%s is required", envExternalFlowAccount)
	}
	cfg.interval = time.Minute
	if !enabled {
		return cfg, nil
	}

	cfg.url = os.Getenv(envExternalFlowURL)
	if !validFlowCollectorURL(cfg.url) {
		return cfg, fmt.Errorf("%s must be an https://host:port URL without credentials, path, query or fragment", envExternalFlowURL)
	}
	cfg.audience = strings.TrimSpace(os.Getenv(envExternalFlowAudience))
	if cfg.audience == "" {
		return cfg, fmt.Errorf("%s is required", envExternalFlowAudience)
	}
	if val, ok := os.LookupEnv(envExternalFlowInterval); ok {
		cfg.interval, err = time.ParseDuration(val)
		// A credential refresh restarts the client's reporting ticker.
		if err != nil || cfg.interval < time.Second || cfg.interval >= externalFlowTokenTTL/2 {
			return cfg, fmt.Errorf("%s must be a duration from 1s to less than %s", envExternalFlowInterval, externalFlowTokenTTL/2)
		}
	}
	cfg.key, err = peerauth.LoadSigningKeyFile(os.Getenv(envExternalFlowKeyFile))
	if err != nil {
		return cfg, fmt.Errorf("%s: %w", envExternalFlowKeyFile, err)
	}
	return cfg, nil
}

func validFlowCollectorURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || (u.Path != "" && u.Path != "/") || strings.ContainsAny(raw, "?#") {
		return false
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" {
		return false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n != 0
}

type flowClaims struct {
	Version   int           `json:"v"`
	Audience  string        `json:"aud"`
	ExpiresAt int64         `json:"exp"`
	AccountID flowAccountID `json:"account_id"`
	PeerID    flowPeerID    `json:"peer_id"`
	WGPubKey  string        `json:"wg_pub_key"`
}

// Each session belongs to one Sync handler. The same goroutine sends the initial
// config, observes subsequent control messages, and renews the flow credential.
type externalFlowSession struct {
	config    *externalFlowConfig
	claims    flowClaims
	relay     *proto.RelayConfig
	authToken []byte
}

func (c *externalFlowConfig) forPeer(peer *nbpeer.Peer, key wgtypes.Key) *externalFlowSession {
	if c.account == "" || c.account != flowAccountID(peer.AccountID) || peer.ID == "" {
		return nil
	}
	return &externalFlowSession{
		config: c,
		claims: flowClaims{Version: 1, Audience: c.audience, AccountID: c.account, PeerID: flowPeerID(peer.ID), WGPubKey: key.String()},
	}
}

func (f *externalFlowSession) apply(cfg *proto.NetbirdConfig) error {
	if f == nil || cfg == nil {
		return nil
	}
	flow := &proto.FlowConfig{Interval: durationpb.New(f.config.interval)}
	if f.config.key != nil {
		claims := f.claims
		claims.ExpiresAt = time.Now().Add(externalFlowTokenTTL).Unix()
		raw, err := json.Marshal(claims)
		if err != nil {
			return fmt.Errorf("marshal external flow claims: %w", err)
		}
		flow.Enabled = true
		flow.Url = f.config.url
		flow.TokenPayload = base64.RawURLEncoding.EncodeToString(raw)
		flow.TokenSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.config.key, []byte(flow.TokenPayload)))
	}
	cfg.Flow = flow
	return nil
}

// Clients interpret absent relay and Signal credentials on a non-nil global config
// as a withdrawal. Carry forward exactly the transport state last sent to this peer.
func (f *externalFlowSession) observe(cfg *proto.NetbirdConfig) {
	if f != nil && f.config.key != nil && cfg != nil {
		f.relay = pb.CloneOf(cfg.Relay)
		f.authToken = bytes.Clone(cfg.AuthToken)
	}
}

func (f *externalFlowSession) refreshTicks() (<-chan time.Time, func()) {
	if f == nil || f.config.key == nil {
		return nil, func() {}
	}
	ticker := time.NewTicker(externalFlowTokenTTL / 2)
	return ticker.C, ticker.Stop
}

func (pu *PeerUpdateHandler) renewExternalFlow(ctx context.Context) error {
	cfg := &proto.NetbirdConfig{Relay: pu.flow.relay, AuthToken: pu.flow.authToken}
	if err := pu.flow.apply(cfg); err != nil {
		pu.cleanupFunc()
		return err
	}
	return pu.SendUpdate(ctx, &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{NetbirdConfig: cfg},
		MessageType: network_map.MessageTypeControlConfig,
	})
}
