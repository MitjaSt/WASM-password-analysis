package main

import (
	"log"
	"mime"
	"net/http"
)

func main() {
	// Browsers reject WASM modules served without this MIME type.
	if err := mime.AddExtensionType(".wasm", "application/wasm"); err != nil {
		log.Fatal(err)
	}

	handler := http.FileServer(http.Dir("web"))
	log.Println("Listening on http://localhost:8092")
	log.Fatal(http.ListenAndServe(":8092", handler))
}
