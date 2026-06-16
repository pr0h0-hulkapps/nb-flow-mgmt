package integrations

import (
	"os"
	"strconv"
	"sync"
	"time"
)

// FlowSettings holds the operator-controlled flow configuration, read once from
// the environment. These mirror the values the proprietary cloud build would
// otherwise manage per-account; here they are set globally by ops.
//
// Environment variables:
//
//	NB_FLOW_URL            receiver endpoint agents stream to        (REQUIRED to activate)
//	                       e.g. http://flow-receiver:9999 or https://flow.example.com
//	NB_FLOW_HMAC_SECRET    shared secret with the receiver           (REQUIRED to activate)
//	NB_FLOW_ENABLED        master on/off                             (default true)
//	NB_FLOW_INTERVAL       how often agents flush events             (default 10s)
//	NB_FLOW_TOKEN_TTL      minted-token lifetime                     (default 1h)
//	NB_FLOW_COUNTERS       send packet/byte counters                 (default true)
//	NB_FLOW_DNS            collect DNS events                        (default false)
//	NB_FLOW_EXIT_NODE      collect on exit nodes                     (default false)
//
// If NB_FLOW_URL or NB_FLOW_HMAC_SECRET is empty, flow stays OFF (safe default):
// ExtendNetBirdConfig returns the config untouched and agents never emit.
type FlowSettings struct {
	url       string
	secret    []byte
	enabled   bool
	interval  time.Duration
	tokenTTL  time.Duration
	counters  bool
	dns       bool
	exitNodes bool
}

var (
	flowOnce sync.Once
	flowCfg  FlowSettings
)

// Flow returns the process-wide flow settings, loading them from the
// environment on first call.
func Flow() FlowSettings {
	flowOnce.Do(func() {
		flowCfg = FlowSettings{
			url:       os.Getenv("NB_FLOW_URL"),
			secret:    []byte(os.Getenv("NB_FLOW_HMAC_SECRET")),
			enabled:   envBool("NB_FLOW_ENABLED", true),
			interval:  envDuration("NB_FLOW_INTERVAL", 10*time.Second),
			tokenTTL:  envDuration("NB_FLOW_TOKEN_TTL", time.Hour),
			counters:  envBool("NB_FLOW_COUNTERS", true),
			dns:       envBool("NB_FLOW_DNS", false),
			exitNodes: envBool("NB_FLOW_EXIT_NODE", false),
		}
	})
	return flowCfg
}

// Active reports whether flow collection is fully configured and enabled.
func (s FlowSettings) Active() bool {
	return s.enabled && s.url != "" && len(s.secret) > 0
}

// URL is the receiver endpoint agents stream flow events to.
func (s FlowSettings) URL() string { return s.url }

// Secret is the HMAC key shared with the receiver.
func (s FlowSettings) Secret() []byte { return s.secret }

// Interval is how often agents flush buffered flow events.
func (s FlowSettings) Interval() time.Duration { return s.interval }

// TokenTTL is the lifetime of a minted per-peer bearer token.
func (s FlowSettings) TokenTTL() time.Duration { return s.tokenTTL }

// Counters reports whether packet/byte counters should be collected.
func (s FlowSettings) Counters() bool { return s.counters }

// Dns reports whether DNS events should be collected.
func (s FlowSettings) Dns() bool { return s.dns }

// ExitNodes reports whether collection on exit nodes is enabled.
func (s FlowSettings) ExitNodes() bool { return s.exitNodes }

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
