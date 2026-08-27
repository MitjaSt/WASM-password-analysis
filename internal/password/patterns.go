package password

import "strings"

const (
	patternKeyboardWalk   = "keyboard walk"
	patternRepeated       = "repeated characters"
	patternSequential     = "sequential characters"
	patternCommonPassword = "common password"
)

var commonPasswords = map[string]struct{}{
	"password": {}, "123456": {}, "12345678": {}, "qwerty": {},
	"abc123": {}, "monkey": {}, "1234567": {}, "letmein": {},
	"trustno1": {}, "dragon": {}, "baseball": {}, "iloveyou": {},
	"master": {}, "sunshine": {}, "ashley": {}, "bailey": {},
	"passw0rd": {}, "shadow": {}, "123123": {}, "654321": {},
	"superman": {}, "michael": {}, "football": {}, "password1": {},
	"111111": {}, "1234": {}, "12345": {}, "123456789": {},
	"welcome": {}, "admin": {}, "login": {}, "hello": {},
	"qwerty123": {}, "pass": {}, "password123": {}, "starwars": {},
	"solo": {}, "princess": {}, "cookie": {}, "cheese": {},
}

var keyboardWalks = []string{
	"qwerty", "qwert", "werty", "asdf", "asdfg", "sdfgh",
	"zxcv", "zxcvb", "cvbnm", "1234", "12345", "123456",
	"4321", "54321", "09876", "qazwsx",
}

type detector func(string) string

// detectPatterns runs independent checks concurrently but writes their results
// into fixed slots, so callers always receive a deterministic pattern order.
func detectPatterns(value string) []string {
	detectors := []detector{
		detectKeyboardWalk,
		detectRepeats,
		detectSequential,
		detectCommon,
	}

	type detection struct {
		index   int
		pattern string
	}
	results := make(chan detection, len(detectors))

	for index, detect := range detectors {
		index, detect := index, detect
		go func() {
			results <- detection{index: index, pattern: detect(value)}
		}()
	}

	ordered := make([]string, len(detectors))
	for range detectors {
		result := <-results
		ordered[result.index] = result.pattern
	}

	patterns := make([]string, 0, len(detectors))
	for _, pattern := range ordered {
		if pattern != "" {
			patterns = append(patterns, pattern)
		}
	}
	return patterns
}

func detectKeyboardWalk(value string) string {
	lower := strings.ToLower(value)
	for _, walk := range keyboardWalks {
		if strings.Contains(lower, walk) {
			return patternKeyboardWalk
		}
	}
	return ""
}

func detectRepeats(value string) string {
	characters := []rune(value)
	for index := 0; index+2 < len(characters); index++ {
		if characters[index] == characters[index+1] && characters[index+1] == characters[index+2] {
			return patternRepeated
		}
	}
	return ""
}

func detectSequential(value string) string {
	characters := []rune(value)
	for index := 0; index+2 < len(characters); index++ {
		first, second, third := characters[index], characters[index+1], characters[index+2]
		if (second == first+1 && third == first+2) || (second == first-1 && third == first-2) {
			return patternSequential
		}
	}
	return ""
}

func detectCommon(value string) string {
	if _, found := commonPasswords[strings.ToLower(value)]; found {
		return patternCommonPassword
	}
	return ""
}
