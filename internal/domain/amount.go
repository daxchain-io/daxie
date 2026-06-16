package domain

import "math/big"

// Amount is a user value as it crosses the wire: a decimal STRING plus an
// optional unit, with the resolved wei kept off the wire (§2.5). The core
// resolves Display+Unit into Wei via internal/ethunit; the boundary never
// carries a float and never carries a bare *big.Int (Wei is json:"-").
type Amount struct {
	Display string   `json:"display"`        // "0.5", "100"
	Unit    string   `json:"unit,omitempty"` // "eth" | "gwei" | "wei"; tokens use decimals
	Wei     *big.Int `json:"-"`              // resolved in core, never serialized raw
}

// NewAmount builds an unresolved Amount (Wei left nil). The core fills Wei after
// parsing the Display string in Unit.
func NewAmount(display, unit string) Amount {
	return Amount{Display: display, Unit: unit}
}

// IsResolved reports whether Wei has been computed.
func (a Amount) IsResolved() bool { return a.Wei != nil }
