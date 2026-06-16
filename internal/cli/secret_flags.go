package cli

import "github.com/spf13/cobra"

// secret_flags.go holds the shared secret-INPUT flag set the wallet/account/
// keystore commands bind (cli-spec §"Secret input rule"). The cardinal rule: a
// secret is NEVER a flag VALUE — flags leak into shell history and `ps` (§3.6).
// These flags select a CHANNEL only: a bool says "read from stdin", a string
// names a file PATH. The actual bytes are read by the core's secret.Acquire from
// os.Stdin / the file / the *_FILE-or-direct env var. The frontend projects these
// channel selections into the service Input structs; it never reads the secret
// itself (the arch matrix forbids frontend→secret).
//
// One flag group per secret kind so a command binds exactly the channels it
// accepts. Each group is a tiny struct with a Bind(cmd) and a value pair the RunE
// reads after parsing.

// passphraseFlags binds --passphrase-stdin / --passphrase-file (the keystore
// passphrase, §3.6).
type passphraseFlags struct {
	stdin bool
	file  string
}

func (f *passphraseFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.stdin, "passphrase-stdin", false, "read the keystore passphrase from stdin")
	fl.StringVar(&f.file, "passphrase-file", "", "read the keystore passphrase from a file (perms checked)")
}

// confirmFlags binds the first-init double-entry confirm channel (§3.3). Present
// only on create/import (the init paths).
type confirmFlags struct {
	stdin bool
	file  string
}

func (f *confirmFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.stdin, "passphrase-confirm-stdin", false, "first-init only: confirm the new keystore passphrase from stdin")
	fl.StringVar(&f.file, "passphrase-confirm-file", "", "first-init only: confirm the new keystore passphrase from a file")
}

// mnemonicFlags binds --mnemonic-stdin / --mnemonic-file (wallet import, §3.5).
type mnemonicFlags struct {
	stdin bool
	file  string
}

func (f *mnemonicFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.stdin, "mnemonic-stdin", false, "read the BIP-39 mnemonic from stdin")
	fl.StringVar(&f.file, "mnemonic-file", "", "read the BIP-39 mnemonic from a file (perms checked)")
}

// bip39Flags binds the optional BIP-39 25th-word passphrase channel (§3.5).
type bip39Flags struct {
	stdin bool
	file  string
}

func (f *bip39Flags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.stdin, "bip39-passphrase-stdin", false, "read the optional BIP-39 passphrase (25th word) from stdin")
	fl.StringVar(&f.file, "bip39-passphrase-file", "", "read the optional BIP-39 passphrase (25th word) from a file")
}

// keyFlags binds --key-stdin / --key-file (standalone import, §3.5).
type keyFlags struct {
	stdin bool
	file  string
}

func (f *keyFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.stdin, "key-stdin", false, "read the raw private key (hex) from stdin")
	fl.StringVar(&f.file, "key-file", "", "read the raw private key (hex) from a file (perms checked)")
}

// newPassphraseFlags binds --new-passphrase-stdin|file (keystore change-passphrase
// rotation target, §3.8) plus its confirm channel.
type newPassphraseFlags struct {
	stdin        bool
	file         string
	confirmStdin bool
	confirmFile  string
}

func (f *newPassphraseFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.stdin, "new-passphrase-stdin", false, "read the NEW keystore passphrase from stdin")
	fl.StringVar(&f.file, "new-passphrase-file", "", "read the NEW keystore passphrase from a file")
	fl.BoolVar(&f.confirmStdin, "new-passphrase-confirm-stdin", false, "confirm the NEW keystore passphrase from stdin")
	fl.StringVar(&f.confirmFile, "new-passphrase-confirm-file", "", "confirm the NEW keystore passphrase from a file")
}
