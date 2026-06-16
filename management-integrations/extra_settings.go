package integrations

import (
	"context"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/types"

	"github.com/netbirdio/netbird/management/server/integrations/extra_settings"
)

type ManagerImpl struct {
}

func NewManager(eventStore activity.Store) extra_settings.Manager {
	return &ManagerImpl{}
}

// GetExtraSettings reports the flow-collection settings. NetBird's settings
// manager overlays ONLY the Flow* fields from this result onto the account's
// stored Extra (see management/server/settings/manager.go), so returning these
// here is what turns flow logging on for self-hosted without a commercial
// license. PeerApproval / IntegratedValidator are handled by core and left
// untouched. Flow* is gorm:"-" in core, i.e. not persisted there — it is
// authoritative here, driven by NB_FLOW_* env (see flowconfig.go).
func (m *ManagerImpl) GetExtraSettings(ctx context.Context, accountID string) (*types.ExtraSettings, error) {
	f := Flow()
	return &types.ExtraSettings{
		FlowEnabled:              f.Active(),
		FlowGroups:               nil, // all peers; scope via ExtendNetBirdConfig if desired
		FlowPacketCounterEnabled: f.Counters(),
		FlowDnsCollectionEnabled: f.Dns(),
		FlowENCollectionEnabled:  f.ExitNodes(),
	}, nil
}

// UpdateExtraSettings is a no-op: flow settings are operator-controlled via
// NB_FLOW_* environment variables, not the dashboard. Returning (false, nil)
// matches the upstream stub's contract (no change persisted).
func (m *ManagerImpl) UpdateExtraSettings(ctx context.Context, accountID, userID string, accountExtraSettings *types.ExtraSettings) (bool, error) {
	return false, nil
}
