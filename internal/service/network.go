package service

import (
	"context"

	"github.com/daxchain-io/daxie/internal/config"
	"github.com/daxchain-io/daxie/internal/domain"
)

// network.go is the M2 `daxie network` use-case surface (cli-spec §network):
// list/add/use/show/remove. A NETWORK is a chain (name, chain-id, native symbol,
// confirmations, default-rpc) — strictly separate from an ENDPOINT (rpc.go,
// §7.5). These are thin over the config accessors (read) + the §7.4 raw-rewrite
// config mutators (add/use/remove); they map the config-owned NetworkView into a
// domain.NetworkRow so the cli never imports config (the arch matrix forbids
// frontend→provider). All the immutability/in-use/read-only policy lives in
// config (one place); service supplies the merged-set inputs those mutators need.

// NetworkList returns every network (built-in + user-defined), sorted by name,
// each marked builtin/default. Read-only.
func (s *Service) NetworkList(ctx context.Context, p domain.Principal, _ domain.NetworkListRequest) (domain.NetworkListResult, error) {
	views := s.cfg.ListNetworks()
	out := domain.NetworkListResult{Networks: make([]domain.NetworkRow, 0, len(views))}
	for _, v := range views {
		out.Networks = append(out.Networks, networkRow(v))
	}
	return out, nil
}

// NetworkShow returns one network by name, or ref.not_found.
func (s *Service) NetworkShow(ctx context.Context, p domain.Principal, req domain.NetworkShowRequest) (domain.NetworkResult, error) {
	v, err := s.cfg.ShowNetwork(req.Name)
	if err != nil {
		return domain.NetworkResult{}, err
	}
	return domain.NetworkResult{Network: networkRow(v)}, nil
}

// NetworkAdd defines a new chain (cli-spec §network). config rejects a duplicate
// (usage.network_exists), an invalid name, and a zero chain-id; with RPCURL it also
// creates the "<name>-default" endpoint and points the network's default-rpc at it.
// A config write → config.read_only on a read-only mount (§2.11).
func (s *Service) NetworkAdd(ctx context.Context, p domain.Principal, req domain.NetworkAddRequest) (domain.NetworkResult, error) {
	n := config.Network{
		ChainID:      req.ChainID,
		Legacy:       req.Legacy,
		NativeSymbol: req.NativeSymbol,
	}
	if err := config.AddNetwork(s.paths, req.Name, n, req.RPCURL); err != nil {
		return domain.NetworkResult{}, err
	}
	// Build the result row from the just-written request (the file write succeeded;
	// re-loading config to confirm would only duplicate work).
	row := domain.NetworkRow{
		Name:         req.Name,
		ChainID:      req.ChainID,
		Legacy:       req.Legacy,
		NativeSymbol: req.NativeSymbol,
	}
	if req.RPCURL != "" {
		row.DefaultRPC = req.Name + "-default"
	}
	return domain.NetworkResult{Network: row}, nil
}

// NetworkUse sets the default network (defaults.network). config refuses an
// unknown network (ref.not_found) against the merged set we pass it, and maps a
// read-only mount to config.read_only (§2.11).
func (s *Service) NetworkUse(ctx context.Context, p domain.Principal, req domain.NetworkUseRequest) (domain.NetworkResult, error) {
	if err := config.UseNetwork(s.paths, req.Name, s.knownNetworks()); err != nil {
		return domain.NetworkResult{}, err
	}
	// Re-show the network (now the default) for the result row.
	v, err := s.cfg.ShowNetwork(req.Name)
	if err != nil {
		// Unreachable in practice (UseNetwork already validated existence); fall
		// back to a minimal row marked default.
		return domain.NetworkResult{Network: domain.NetworkRow{Name: req.Name, Default: true}}, nil
	}
	row := networkRow(v)
	row.Default = true
	return domain.NetworkResult{Network: row}, nil
}

// NetworkRemove removes a user network. config refuses a built-in
// (usage.builtin_immutable) and a user network still referenced by endpoints
// unless Force (usage.network_in_use); we supply the merged referencing set. A
// config write → config.read_only on a read-only mount.
func (s *Service) NetworkRemove(ctx context.Context, p domain.Principal, req domain.NetworkRemoveRequest) (domain.NetworkRemoveResult, error) {
	referencing := s.cfg.EndpointsReferencing(req.Name)
	if err := config.RemoveNetwork(s.paths, req.Name, req.Force, referencing); err != nil {
		return domain.NetworkRemoveResult{}, err
	}
	return domain.NetworkRemoveResult{Name: req.Name, Removed: true}, nil
}

// knownNetworks is the merged network-name set (built-in + user) the config
// mutators check membership against.
func (s *Service) knownNetworks() map[string]bool {
	known := make(map[string]bool, len(s.cfg.Networks))
	for name := range s.cfg.Networks {
		known[name] = true
	}
	return known
}

// networkRow maps a config.NetworkView into the domain wire row.
func networkRow(v config.NetworkView) domain.NetworkRow {
	return domain.NetworkRow{
		Name:          v.Name,
		ChainID:       v.ChainID,
		Confirmations: v.Confirmations,
		DefaultRPC:    v.DefaultRPC,
		Legacy:        v.Legacy,
		NativeSymbol:  v.NativeSymbol,
		ENSRegistry:   v.ENSRegistry,
		Builtin:       v.Builtin,
		Default:       v.Default,
	}
}
