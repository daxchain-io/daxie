package keys

import "context"

// Info reports keystore metadata (§10.2): path, format version, object counts, and
// the KDF template. No unlock required.
func (s *Store) Info(ctx context.Context) (Info, error) {
	out := Info{Path: s.dir}
	man, err := s.loadManifest()
	if err != nil {
		return Info{}, err
	}
	if man != nil {
		out.Initialized = true
		out.Format = man.Format
		out.KDF = man.KDFDefaults.KDF
		out.ScryptN = man.KDFDefaults.N
	}
	m, err := s.loadMeta()
	if err != nil {
		return Info{}, err
	}
	out.Wallets = len(m.Wallets)
	out.Accounts = len(m.Accounts)
	for _, w := range m.Wallets {
		out.HDAccounts += len(w.Accounts)
	}
	return out, nil
}
