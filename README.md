# Password Analyzer — Go + WebAssembly

WebAssembly project that runs password analysis entirely in the browser, no server-side processing involved

## What it does

- **Entropy** — bits of randomness based on character set size × length
- **Crack time** — estimated brute-force time at 10 billion guesses/sec (GPU)
- **Pattern detection** — keyboard walks, repeated characters, sequential runs, common passwords
- **Strength label** — Weak / Fair / Strong / Very Strong
- **Known breach check** — optional Have I Been Pwned lookup using a five-character SHA-1 prefix

Pattern checks fan out as goroutines and collect via a channel, demonstrating Go's concurrency model inside the browser's single-threaded WASM environment.

Strength scoring is calibrated so that, before pattern penalties, Fair begins
at 45 bits of entropy, Strong at 60 bits, and Very Strong at 75 bits. Under the
displayed 10-billion-guesses-per-second assumption, a Strong rating therefore
requires an estimated brute-force time measured in years rather than seconds.

Local analysis is immediate and does not require a network connection. After the
password field loses focus, the browser hashes the password locally and sends
only the first five SHA-1 characters to the Pwned Passwords range API. The
request asks for response padding, times out after one second, and never blocks
or replaces the local result.

## Requirements

- [Go](https://go.dev/dl/) 1.21 or later
- Node.js 20 or later (tests only; there are no npm dependencies)
- `make`

## Run locally

```bash
# 1. Build the WASM module
make build

# 2. Start the dev file server (serves web/ on :8092)
make serve
```

Then open [http://localhost:8092](http://localhost:8092).

> **Note:** If port 8092 is already in use (e.g. by Docker), edit `cmd/server/main.go` and change `:8092` to any free port.

## Test

```bash
make test # All tests

make test-go # Go only
make test-web # Web only
```
