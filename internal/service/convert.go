package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/ethunit"
)

// Convert is the one M0 signing-free use case: eth/gwei/wei unit conversion so
// agents never hand-roll 10^18 math (cli-spec §Utility). It is PURE — no
// provider, no clock, no I/O — so it satisfies the §2.3 determinism guard
// trivially and delegates all value math to internal/ethunit (no float, exact
// *big.Int decimals).
//
// Source-unit precedence: an explicit unit suffix on the amount ("1.5eth") wins;
// otherwise req.From names the source unit; a bare number with neither is a usage
// error (the source unit is required — there is no implicit default, because
// "100" alone is ambiguous between eth/gwei/wei).
func (s *Service) Convert(ctx context.Context, req domain.ConvertRequest) (domain.ConvertResult, error) {
	value, suffix := ethunit.SplitAmountUnit(strings.TrimSpace(req.Amount))

	fromName := suffix
	if fromName == "" {
		fromName = strings.TrimSpace(req.From)
	} else if f := strings.TrimSpace(req.From); f != "" && !strings.EqualFold(f, suffix) {
		// Both a suffix and a From were given and they disagree — refuse rather
		// than silently picking one (J4: be honest about ambiguous input).
		return domain.ConvertResult{}, domain.Newf(
			"usage.convert.unit_conflict",
			"amount suffix %q conflicts with from-unit %q", suffix, f,
		)
	}

	if fromName == "" {
		return domain.ConvertResult{}, domain.New(
			"usage.convert.missing_unit",
			"source unit required: suffix the amount (e.g. \"1.5eth\") or pass a from-unit",
		)
	}
	if strings.TrimSpace(req.To) == "" {
		return domain.ConvertResult{}, domain.New(
			"usage.convert.missing_to",
			"target unit required: eth, gwei, or wei",
		)
	}

	from, err := ethunit.ParseUnit(fromName)
	if err != nil {
		return domain.ConvertResult{}, domain.Wrap(
			"usage.convert.bad_unit",
			fmt.Sprintf("unknown source unit %q (want eth|gwei|wei)", fromName), err,
		)
	}
	to, err := ethunit.ParseUnit(strings.TrimSpace(req.To))
	if err != nil {
		return domain.ConvertResult{}, domain.Wrap(
			"usage.convert.bad_unit",
			fmt.Sprintf("unknown target unit %q (want eth|gwei|wei)", req.To), err,
		)
	}

	wei, err := ethunit.ParseAmount(value, from)
	if err != nil {
		return domain.ConvertResult{}, domain.Wrap(
			"usage.convert.bad_amount",
			fmt.Sprintf("cannot parse %q as %s", value, from), err,
		)
	}

	out := ethunit.FormatAmount(wei, to)

	return domain.ConvertResult{
		Input: value + " " + from.String(),
		Wei:   wei.String(),
		From:  from.String(),
		To:    to.String(),
		Value: out,
	}, nil
}
