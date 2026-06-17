package chain

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/fsx"
)

// buildTLSConfig assembles a *tls.Config for an endpoint from the mTLS file
// PATHS on Options (design §7.5; requirements §6). It returns:
//
//   - (nil, nil) when no TLS material is configured (the default system TLS for
//     an https:// URL still applies — this only customizes client auth / CA);
//   - a config with a client certificate (mutual TLS) when Cert+Key are set;
//   - a config with a custom RootCAs pool when CA is set (else system roots).
//
// The client KEY file is permission-checked with fsx.CheckPerms (the §7.9 rule:
// hard-fail on world/group-write, fsGroup carve-out for group-read) BEFORE it is
// loaded, exactly like a passphrase file — a leaked mTLS key is a leaked
// credential. Cert and CA are public material and are not perms-checked.
//
// Misconfigurations fail CLOSED with typed domain errors: an insecure key
// surfaces keystore.perms_insecure (exit 12) from fsx; a missing/garbled
// cert/key/CA surfaces config.invalid (exit 2) so the operator gets an
// actionable message instead of an opaque transport failure mid-dial.
func buildTLSConfig(o Options) (*tls.Config, error) {
	hasCert := o.TLSCert != "" || o.TLSKey != ""
	if !hasCert && o.TLSCA == "" {
		return nil, nil
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if hasCert {
		// Both halves of a client identity are required; one without the other is
		// an operator mistake, not a partial config we silently accept.
		if o.TLSCert == "" || o.TLSKey == "" {
			return nil, domain.New(
				domain.CodeConfigInvalid,
				"mTLS requires both tls.cert and tls.key; only one was provided",
			)
		}
		// Perms-check the private key BEFORE loading it (a secret-bearing file).
		if err := fsx.CheckPerms(o.TLSKey); err != nil {
			return nil, err // already a typed keystore.perms_insecure (exit 12)
		}
		pair, err := tls.LoadX509KeyPair(o.TLSCert, o.TLSKey)
		if err != nil {
			return nil, domain.WithData(
				domain.Wrap(
					domain.CodeConfigInvalid,
					"failed to load mTLS client cert/key: "+err.Error(),
					err,
				),
				map[string]any{"cert": o.TLSCert, "key": o.TLSKey},
			)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}

	if o.TLSCA != "" {
		pem, err := os.ReadFile(o.TLSCA)
		if err != nil {
			return nil, domain.WithData(
				domain.Wrap(
					domain.CodeConfigInvalid,
					"failed to read mTLS CA bundle: "+err.Error(),
					err,
				),
				map[string]any{"ca": o.TLSCA},
			)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, domain.WithData(
				domain.New(
					domain.CodeConfigInvalid,
					"mTLS CA bundle "+o.TLSCA+" contains no valid PEM certificates",
				),
				map[string]any{"ca": o.TLSCA},
			)
		}
		cfg.RootCAs = pool
	}

	return cfg, nil
}
