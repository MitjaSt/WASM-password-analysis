GOROOT     := $(shell go env GOROOT)
# wasm_exec.js moved in newer Go versions; pick whichever exists
WASM_EXEC  := $(firstword $(wildcard \
	$(GOROOT)/misc/wasm/wasm_exec.js \
	$(GOROOT)/lib/wasm/wasm_exec.js))

.PHONY: all build copy-js test test-go test-web serve clean

all: build copy-js

build:
	GOOS=js GOARCH=wasm go build -o web/main.wasm ./cmd/wasm

copy-js:
	cp $(WASM_EXEC) web/wasm_exec.js

test: test-go test-web

test-go:
	go test ./...

test-web:
	npm test

serve:
	go run ./cmd/server

clean:
	rm -f web/main.wasm web/wasm_exec.js
