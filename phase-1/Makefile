.PHONY: test build vet lint clean

# Run unit tests with the race detector. -count=1 disables the test cache
# so we always get a fresh result.
test:
	go test ./... -count=1 -race

# Build the single binary. Output goes to bin/ which is .gitignored.
build:
	go build -o bin/nodeagent ./cmd/nodeagent

# Built-in static checks. Always free, no install needed.
vet:
	go vet ./...

# Heavier static checks. Requires golangci-lint; install with:
#     brew install golangci-lint
lint:
	golangci-lint run

clean:
	rm -rf bin
