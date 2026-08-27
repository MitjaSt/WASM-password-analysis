package password

import (
	"reflect"
	"testing"
)

func TestPatternDetectors(t *testing.T) {
	tests := []struct {
		name   string
		detect detector
		value  string
		want   string
	}{
		{name: "keyboard walk", detect: detectKeyboardWalk, value: "XX-AsDf-YY", want: patternKeyboardWalk},
		{name: "no keyboard walk", detect: detectKeyboardWalk, value: "random", want: ""},
		{name: "repeated characters", detect: detectRepeats, value: "baaad", want: patternRepeated},
		{name: "unicode repeated characters", detect: detectRepeats, value: "xöööx", want: patternRepeated},
		{name: "ascending sequence", detect: detectSequential, value: "xabcx", want: patternSequential},
		{name: "descending sequence", detect: detectSequential, value: "x321x", want: patternSequential},
		{name: "no sequence", detect: detectSequential, value: "acex", want: ""},
		{name: "common is case insensitive", detect: detectCommon, value: "PassWord", want: patternCommonPassword},
		{name: "uncommon password", detect: detectCommon, value: "not-in-the-list", want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.detect(test.value); got != test.want {
				t.Errorf("detector(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

func TestDetectPatternsIsDeterministic(t *testing.T) {
	want := []string{patternKeyboardWalk, patternSequential, patternCommonPassword}
	for iteration := 0; iteration < 100; iteration++ {
		if got := detectPatterns("qwerty123"); !reflect.DeepEqual(got, want) {
			t.Fatalf("detectPatterns() = %v, want %v", got, want)
		}
	}
}
