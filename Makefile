.PHONY: test build build-linux vet lint clean

# Run unit tests with the race detector. -count=1 disables the test cache
# so we always get a fresh result.
test:
	go test ./... -count=1 -race

# Build the single binary for the host platform. Output goes to bin/
# which is .gitignored.
build:
	go build -o bin/nodeagent ./cmd/nodeagent

# Cross-compile for linux/amd64 (the appliance target).
# CGO_ENABLED=0 produces a fully static ELF that runs on minimal NixOS
# without depending on host libc. Do NOT relax this — a CGO-linked
# binary will silently fail on the target with "no such file or
# directory" because the dynamic loader path differs from glibc.
build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/nodeagent-linux-amd64 ./cmd/nodeagent

# Built-in static checks. Always free, no install needed.
vet:
	go vet ./...

# Heavier static checks. Requires golangci-lint; install with:
#     brew install golangci-lint
lint:
	golangci-lint run

clean:
	rm -rf bin
