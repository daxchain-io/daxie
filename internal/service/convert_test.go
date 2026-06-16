package service

import (
	"context"
	"errors"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

func TestConvert(t *testing.T) {
	s := &Service{clock: zeroClock} // Convert is pure; no Open needed.
	ctx := context.Background()

	tests := []struct {
		name      string
		req       domain.ConvertRequest
		wantWei   string
		wantValue string
		wantFrom  string
		wantTo    string
	}{
		{
			name:      "eth to wei via suffix",
			req:       domain.ConvertRequest{Amount: "1.5eth", To: "wei"},
			wantWei:   "1500000000000000000",
			wantValue: "1500000000000000000",
			wantFrom:  "eth", wantTo: "wei",
		},
		{
			name:      "wei to gwei via suffix",
			req:       domain.ConvertRequest{Amount: "30000000000wei", To: "gwei"},
			wantWei:   "30000000000",
			wantValue: "30",
			wantFrom:  "wei", wantTo: "gwei",
		},
		{
			name:      "gwei to eth via from-field",
			req:       domain.ConvertRequest{Amount: "1000000000", From: "gwei", To: "eth"},
			wantWei:   "1000000000000000000",
			wantValue: "1",
			wantFrom:  "gwei", wantTo: "eth",
		},
		{
			name:      "eth to gwei",
			req:       domain.ConvertRequest{Amount: "1eth", To: "gwei"},
			wantWei:   "1000000000000000000",
			wantValue: "1000000000",
			wantFrom:  "eth", wantTo: "gwei",
		},
		{
			name:      "round-trip eth->wei->eth keeps value",
			req:       domain.ConvertRequest{Amount: "0.123456789012345678eth", To: "wei"},
			wantWei:   "123456789012345678",
			wantValue: "123456789012345678",
			wantFrom:  "eth", wantTo: "wei",
		},
		{
			name:      "case-folded unit",
			req:       domain.ConvertRequest{Amount: "2ETH", To: "WEI"},
			wantWei:   "2000000000000000000",
			wantValue: "2000000000000000000",
			wantFrom:  "eth", wantTo: "wei",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.Convert(ctx, tt.req)
			if err != nil {
				t.Fatalf("Convert(%+v): %v", tt.req, err)
			}
			if got.Wei != tt.wantWei {
				t.Errorf("Wei = %q, want %q", got.Wei, tt.wantWei)
			}
			if got.Value != tt.wantValue {
				t.Errorf("Value = %q, want %q", got.Value, tt.wantValue)
			}
			if got.From != tt.wantFrom {
				t.Errorf("From = %q, want %q", got.From, tt.wantFrom)
			}
			if got.To != tt.wantTo {
				t.Errorf("To = %q, want %q", got.To, tt.wantTo)
			}
		})
	}
}

func TestConvertErrors(t *testing.T) {
	s := &Service{clock: zeroClock}
	ctx := context.Background()

	tests := []struct {
		name     string
		req      domain.ConvertRequest
		wantCode string // canonical dotted prefix
	}{
		{"bad target unit", domain.ConvertRequest{Amount: "1eth", To: "foo"}, "usage.convert.bad_unit"},
		{"bad source unit", domain.ConvertRequest{Amount: "1", From: "foo", To: "wei"}, "usage.convert.bad_unit"},
		{"missing source unit", domain.ConvertRequest{Amount: "100", To: "wei"}, "usage.convert.missing_unit"},
		{"missing target unit", domain.ConvertRequest{Amount: "1eth"}, "usage.convert.missing_to"},
		{"unit conflict", domain.ConvertRequest{Amount: "1eth", From: "gwei", To: "wei"}, "usage.convert.unit_conflict"},
		// A valid unit but a malformed numeric part exercises the bad_amount path
		// (vs "abceth", whose lack of a numeric prefix is a bad_unit).
		{"unparseable amount", domain.ConvertRequest{Amount: "1.2.3", From: "eth", To: "wei"}, "usage.convert.bad_amount"},
		{"non-numeric is bad unit", domain.ConvertRequest{Amount: "abceth", To: "wei"}, "usage.convert.bad_unit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.Convert(ctx, tt.req)
			if err == nil {
				t.Fatalf("Convert(%+v) = nil error, want %s", tt.req, tt.wantCode)
			}
			var de *domain.Error
			if !errors.As(err, &de) {
				t.Fatalf("error is not *domain.Error: %v", err)
			}
			if de.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", de.Code, tt.wantCode)
			}
			// Every convert error maps to exit 2 (USAGE) through the registry.
			if de.Exit != domain.ExitUsage {
				t.Errorf("exit = %d, want %d (USAGE)", de.Exit, domain.ExitUsage)
			}
		})
	}
}
