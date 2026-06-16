package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/fsx"
)

// ResolveSecretRefs is the ONLY config-side secret resolver (§7.5). It expands a
// value that may embed placeholders, returning the resolved string. The config
// file stores the REFERENCE, never the resolved secret; resolution is meant to
// happen in-memory at connect time (service), so the result lives only inside the
// caller's frame and is never written back.
//
// Grammar (§7.5):
//
//	${env:NAME}     -> value of env var NAME (missing => secret.unresolved)
//	${file:/abs}    -> file contents, one trailing \n or \r\n stripped, perms checked
//	${file:~/rel}   -> ~ expands to the home dir, then as ${file:}
//	$${             -> a literal "${" (the escape)
//
// An unknown scheme (e.g. ${vault:…}) is a hard error, not a passthrough, so a
// new scheme can be added later without ambiguity.
func ResolveSecretRefs(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); {
		// Escape: "$${" -> literal "${".
		if strings.HasPrefix(s[i:], "$${") {
			b.WriteString("${")
			i += 3
			continue
		}
		if strings.HasPrefix(s[i:], "${") {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return "", domain.Newf(domain.CodeSecretUnresolved,
					"unterminated secret reference in %q (missing '}')", s)
			}
			inner := s[i+2 : i+end] // between "${" and "}"
			resolved, err := resolveOneRef(inner)
			if err != nil {
				return "", err
			}
			b.WriteString(resolved)
			i += end + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), nil
}

// resolveOneRef resolves the inner text of one ${…} reference (without braces).
func resolveOneRef(inner string) (string, error) {
	scheme, arg, ok := strings.Cut(inner, ":")
	if !ok {
		return "", domain.Newf(domain.CodeSecretUnresolved,
			"secret reference ${%s} has no scheme (expected ${env:…} or ${file:…})", inner)
	}
	switch scheme {
	case "env":
		if arg == "" {
			return "", domain.New(domain.CodeSecretUnresolved, "${env:} requires a variable name")
		}
		v, present := lookupEnv(arg)
		if !present || v == "" {
			return "", domain.Newf(domain.CodeSecretUnresolved,
				"environment variable %q referenced by ${env:%s} is not set", arg, arg)
		}
		return v, nil
	case "file":
		return resolveFileRef(arg)
	default:
		return "", domain.Newf(domain.CodeSecretUnresolved,
			"unknown secret-reference scheme %q in ${%s} (only env, file are supported)", scheme, inner)
	}
}

// resolveFileRef reads a ${file:…} reference: expands a leading ~, permission-
// checks the file (§7.9), reads it, and strips exactly one trailing \n or \r\n.
func resolveFileRef(path string) (string, error) {
	if path == "" {
		return "", domain.New(domain.CodeSecretUnresolved, "${file:} requires a path")
	}
	expanded, err := expandHome(path)
	if err != nil {
		return "", err
	}
	if err := fsx.CheckPerms(expanded); err != nil {
		// CheckPerms returns a *domain.Error on a hard failure; surface it
		// (exit 2 via its own code) rather than masking it as secret.unresolved.
		return "", err
	}
	data, err := os.ReadFile(expanded) // #nosec G304 -- expanded is the operator-supplied ${file:} secret-ref path, perms-checked just above
	if err != nil {
		return "", domain.Wrap(domain.CodeSecretUnresolved,
			"reading ${file:"+path+"}: "+err.Error(), err)
	}
	return stripOneTrailingNewline(string(data)), nil
}

// expandHome expands a leading "~/" (or a bare "~") to the home directory.
func expandHome(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := homeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

// stripOneTrailingNewline removes exactly one trailing \n or \r\n (K8s Secrets
// and echo append one). It does not strip more than one.
func stripOneTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\r\n") {
		return s[:len(s)-2]
	}
	if strings.HasSuffix(s, "\n") {
		return s[:len(s)-1]
	}
	return s
}
