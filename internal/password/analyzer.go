// Package password analyzes password strength without depending on a browser
// or WebAssembly. Browser-specific code belongs in cmd/wasm.
package password

import (
	"math"
	"unicode/utf8"
)

const (
	guessesPerSecond  = 1e10
	minimumScoredBits = 30.0
	maximumScoredBits = 90.0
)

// Result contains the values displayed by the password analyzer UI.
type Result struct {
	Entropy      float64  `json:"entropy"`
	TimeEstimate string   `json:"timeEstimate"`
	Patterns     []string `json:"patterns"`
	Score        int      `json:"score"`
	Label        string   `json:"label"`
	CharsetSize  int      `json:"charsetSize"`
}

// Analyze calculates entropy, estimates brute-force time, and applies pattern
// penalties. It is safe to call independently of the WASM adapter.
func Analyze(value string) Result {
	if value == "" {
		return Result{Patterns: []string{}}
	}

	patterns := detectPatterns(value)
	charset := charsetSize(value)
	entropy := calcEntropy(value, charset)
	crackTime := math.Pow(2, entropy) / guessesPerSecond

	// Entropy below 30 bits earns almost no strength score. With no pattern
	// penalties, Fair starts at 45 bits, Strong at 60 bits, and Very Strong at
	// 75 bits. At 10 billion guesses per second those boundaries represent
	// roughly an hour, several years, and more than a hundred thousand years.
	rawScore := (entropy - minimumScoredBits) /
		(maximumScoredBits - minimumScoredBits) * 100
	score := int(math.Max(0, math.Min(rawScore, 100))) - len(patterns)*15
	if score < 0 {
		score = 0
	}

	label := scoreLabel(score)
	if containsPattern(patterns, patternCommonPassword) {
		label = "Weak"
		if score > 24 {
			score = 24
		}
	}

	return Result{
		Entropy:      entropy,
		TimeEstimate: formatTime(crackTime),
		Patterns:     patterns,
		Score:        score,
		Label:        label,
		CharsetSize:  charset,
	}
}

func charsetSize(value string) int {
	var lower, upper, digit, symbol bool
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
			lower = true
		case character >= 'A' && character <= 'Z':
			upper = true
		case character >= '0' && character <= '9':
			digit = true
		default:
			symbol = true
		}
	}

	size := 0
	if lower {
		size += 26
	}
	if upper {
		size += 26
	}
	if digit {
		size += 10
	}
	if symbol {
		size += 32
	}
	return size
}

func calcEntropy(value string, charset int) float64 {
	if charset == 0 {
		return 0
	}
	return math.Log2(float64(charset)) * float64(utf8.RuneCountInString(value))
}

func scoreLabel(score int) string {
	switch {
	case score >= 75:
		return "Very Strong"
	case score >= 50:
		return "Strong"
	case score >= 25:
		return "Fair"
	default:
		return "Weak"
	}
}

func containsPattern(patterns []string, wanted string) bool {
	for _, pattern := range patterns {
		if pattern == wanted {
			return true
		}
	}
	return false
}
