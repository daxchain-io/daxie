package domain

// ConvertRequest is the input to `daxie convert <amount> <to-unit>` (the M0 use
// case). The value crosses as a STRING (no float on the wire, §2.5). The amount
// may carry an embedded source unit ("1.5eth") OR From may name it; the parser
// in service/ethunit decides precedence (an explicit From overrides a suffix
// only when the amount has no suffix — see service.Convert).
type ConvertRequest struct {
	Amount string `json:"amount" jsonschema:"value with optional unit suffix, e.g. \"1.5eth\" or \"100\""`
	From   string `json:"from,omitempty" jsonschema:"source unit when not suffixed: eth|gwei|wei"`
	To     string `json:"to" jsonschema:"target unit: eth|gwei|wei"`
}

// ConvertResult is the output of a conversion. Every numeric field is an exact
// decimal string (no float). Wei is the canonical *big.Int rendered as a decimal
// string; Value is the amount expressed in the To unit.
type ConvertResult struct {
	Input string `json:"input"` // echoed normalized input, e.g. "1.5 eth"
	Wei   string `json:"wei"`   // canonical wei as a decimal string
	From  string `json:"from"`  // resolved source unit
	To    string `json:"to"`    // target unit
	Value string `json:"value"` // result in To units, exact decimal string
}
