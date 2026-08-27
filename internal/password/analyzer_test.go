package password

import (
	"math"
	"reflect"
	"testing"
)

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		wantPatterns []string
		wantScore    int
		wantLabel    string
		wantCharset  int
	}{
		{
			name:         "empty password",
			value:        "",
			wantPatterns: []string{},
			wantScore:    0,
			wantLabel:    "",
			wantCharset:  0,
		},
		{
			name:         "common password is capped at weak",
			value:        "password",
			wantPatterns: []string{patternCommonPassword},
			wantScore:    0,
			wantLabel:    "Weak",
			wantCharset:  26,
		},
		{
			name:         "multiple patterns retain detector order",
			value:        "qwerty123",
			wantPatterns: []string{patternKeyboardWalk, patternSequential, patternCommonPassword},
			wantScore:    0,
			wantLabel:    "Weak",
			wantCharset:  36,
		},
		{
			name:         "mixed character sets produce a strong result",
			value:        "Tr0ub4dor&3",
			wantPatterns: []string{},
			wantScore:    70,
			wantLabel:    "Strong",
			wantCharset:  94,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Analyze(test.value)
			if !reflect.DeepEqual(got.Patterns, test.wantPatterns) {
				t.Errorf("Patterns = %v, want %v", got.Patterns, test.wantPatterns)
			}
			if got.Score != test.wantScore {
				t.Errorf("Score = %d, want %d", got.Score, test.wantScore)
			}
			if got.Label != test.wantLabel {
				t.Errorf("Label = %q, want %q", got.Label, test.wantLabel)
			}
			if got.CharsetSize != test.wantCharset {
				t.Errorf("CharsetSize = %d, want %d", got.CharsetSize, test.wantCharset)
			}
		})
	}
}

func TestAnalyzeDoesNotRateQuicklyCrackedPasswordAsStrong(t *testing.T) {
	got := Analyze("passwor")

	if got.TimeEstimate != "803 ms" {
		t.Errorf("TimeEstimate = %q, want %q", got.TimeEstimate, "803 ms")
	}
	if got.Score != 4 {
		t.Errorf("Score = %d, want 4", got.Score)
	}
	if got.Label != "Weak" {
		t.Errorf("Label = %q, want %q", got.Label, "Weak")
	}
}

func TestAnalyzeCountsUnicodeCharactersRatherThanBytes(t *testing.T) {
	got := Analyze("äää")

	if got.Entropy != 15 {
		t.Errorf("Entropy = %v, want 15", got.Entropy)
	}
	if !reflect.DeepEqual(got.Patterns, []string{patternRepeated}) {
		t.Errorf("Patterns = %v, want repeated characters", got.Patterns)
	}
}

func TestCharsetSize(t *testing.T) {
	tests := map[string]int{
		"":      0,
		"lower": 26,
		"UPPER": 26,
		"123":   10,
		"!@#":   32,
		"aA1!":  94,
		"café":  58,
	}

	for value, want := range tests {
		t.Run(value, func(t *testing.T) {
			if got := charsetSize(value); got != want {
				t.Errorf("charsetSize(%q) = %d, want %d", value, got, want)
			}
		})
	}
}

func TestCalcEntropy(t *testing.T) {
	got := calcEntropy("abcd", 26)
	want := math.Log2(26) * 4
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("calcEntropy() = %v, want %v", got, want)
	}
}
