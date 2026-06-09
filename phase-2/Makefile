.PHONY: test build build-linux vet lint clean

# Run unit tests with the race detector. -count=1 disables the test cache.
test:
	go test ./... -count=1 -race

# Build the single binary for the host platform.
build:
	go build -o bin/nodeagent ./cmd/nodeagent

# Cross-compile for linux/amd64 (the appliance target).
# CGO_ENABLED=0 produces a fully static ELF that runs on minimal NixOS
# without depending on host libc.
build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/nodeagent-linux-amd64 ./cmd/nodeagent

vet:
	go vet ./...

# Heavier static checks. Install: brew install golangci-lint
lint:
	golangci-lint run

clean:
	rm -rf bin
