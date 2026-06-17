package policy

// export_change.go exposes the small set of constructors the composition root
// (internal/service) needs to build a Change/Limits without reaching into the
// engine's internal tri-state encoding. The "no limit" sentinel that the sealed
// body renders as a literal JSON null is an implementation detail of file.go; the
// service layer expresses the §4.7 `none` literal through NoLimit() rather than
// hand-constructing the sentinel string.

// NoLimit returns the tri-state "explicit no limit on this network" value for a
// Limits amount field (*string). It corresponds to the §4.7 `none` CLI literal and
// is distinct from a nil pointer (which means "inherit the default / leave
// unchanged"). The sealed body writer renders it as a literal JSON null (§4.5).
func NoLimit() *string { return nullStr() }

// NullSentinel returns the raw in-memory marker NoLimit() carries. It exists so a
// caller that already holds a *string can test it for the explicit-null state
// without importing the unexported constant. Prefer NoLimit() for construction.
func NullSentinel() string { return nullSentinel }
