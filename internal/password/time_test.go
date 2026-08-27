package password

import (
	"math"
	"testing"
)

func TestFormatTime(t *testing.T) {
	const day = 24 * 60 * 60
	const year = 365 * day

	tests := []struct {
		name    string
		seconds float64
		want    string
	}{
		{name: "instant", seconds: 0.0001, want: "instantly"},
		{name: "milliseconds", seconds: 0.5, want: "500 ms"},
		{name: "seconds", seconds: 30, want: "30 seconds"},
		{name: "minutes", seconds: 2 * 60, want: "2 minutes"},
		{name: "hours", seconds: 2 * 60 * 60, want: "2 hours"},
		{name: "days", seconds: 2 * day, want: "2 days"},
		{name: "years", seconds: 2 * year, want: "2 years"},
		{name: "centuries", seconds: 200 * year, want: "2 centuries"},
		{name: "infinite", seconds: math.Inf(1), want: "longer than the universe"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := formatTime(test.seconds); got != test.want {
				t.Errorf("formatTime(%v) = %q, want %q", test.seconds, got, test.want)
			}
		})
	}
}
