package config

import (
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"

	flowsettings "github.com/netbirdio/management-integrations/integrations"
	"github.com/netbirdio/management-integrations/integrations/flowtoken"
)

// ExtendNetBirdConfig injects the FlowConfig into a peer's sync config so the
// (stock, unmodified) NetBird agent starts streaming flow events to our
// receiver. This is the upstream integration seam — called from
// management/internals/shared/grpc/conversion.go — and replaces the no-op stub.
//
// It is a pure function of its inputs plus process env: given FlowEnabled and a
// configured receiver URL + HMAC secret, it mints a short-lived per-peer bearer
// token and sets config.Flow. With flow disabled or unconfigured it returns the
// config untouched, so the default behaviour is exactly upstream.
func ExtendNetBirdConfig(peerID string, peerGroups []string, config *proto.NetbirdConfig, extraSettings *types.ExtraSettings) *proto.NetbirdConfig {
	if config == nil || extraSettings == nil || !extraSettings.FlowEnabled {
		return config
	}

	s := flowsettings.Flow()
	if !s.Active() {
		return config
	}

	// Optional group scoping: if FlowGroups is set, only peers in one of those
	// groups receive a flow config. Empty => all peers.
	if len(extraSettings.FlowGroups) > 0 && !intersects(peerGroups, extraSettings.FlowGroups) {
		return config
	}

	payload, signature, err := flowtoken.MintWithTTL(s.Secret(), peerID, "", time.Now(), s.TokenTTL())
	if err != nil {
		// Fail safe: no token => don't enable flow for this peer.
		return config
	}

	config.Flow = &proto.FlowConfig{
		Url:                s.URL(),
		TokenPayload:       payload,
		TokenSignature:     signature,
		Interval:           durationpb.New(s.Interval()),
		Enabled:            true,
		Counters:           extraSettings.FlowPacketCounterEnabled,
		DnsCollection:      extraSettings.FlowDnsCollectionEnabled,
		ExitNodeCollection: extraSettings.FlowENCollectionEnabled,
	}
	return config
}

func intersects(a, b []string) bool {
	set := make(map[string]struct{}, len(b))
	for _, x := range b {
		set[x] = struct{}{}
	}
	for _, x := range a {
		if _, ok := set[x]; ok {
			return true
		}
	}
	return false
}
