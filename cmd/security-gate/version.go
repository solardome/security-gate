package main

// version is set at build time via -ldflags="-X main.version=vX.Y.Z".
// Falls back to "dev" when built without the flag (local builds, `go run`).
var version = "dev"
