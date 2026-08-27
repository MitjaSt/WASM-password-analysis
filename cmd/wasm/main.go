//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"password-analyzer/internal/password"
)

// coerceToString accepts the JavaScript primitive values that can sensibly be
// analyzed as passwords. Objects, functions, null, and undefined are rejected.
func coerceToString(v js.Value) (string, bool) {
	switch v.Type() {
	case js.TypeString:
		return v.String(), true
	case js.TypeNumber, js.TypeBoolean:
		return v.Call("toString").String(), true
	default:
		return "", false
	}
}

func main() {
	analyzePassword := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) == 0 {
			return "{}"
		}

		value, ok := coerceToString(args[0])
		if !ok {
			return "{}"
		}

		result, err := json.Marshal(password.Analyze(value))
		if err != nil {
			return "{}"
		}
		return string(result)
	})
	js.Global().Set("analyzePassword", analyzePassword)

	select {} // Keep the Go runtime and JavaScript callback alive.
}
