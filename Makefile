# CodexSentinel Makefile

# Variables
BINARY_NAME=codex
BUILD_DIR=build
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-ldflags "-X github.com/Voskan/codexsentinel/internal/version.Version=$(VERSION) -X github.com/Voskan/codexsentinel/internal/version.BuildTime=$(BUILD_TIME) -X github.com/Voskan/codexsentinel/internal/version.GitCommit=$(GIT_COMMIT)"

# Default target
.PHONY: all
all: clean build

# Build the application
.PHONY: build
build:
	@echo "Building CodexSentinel..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/codex-cli

# Build for multiple platforms
.PHONY: build-all
build-all: clean
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	
	# Linux
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/codex-cli
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/codex-cli
	
	# macOS
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/codex-cli
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/codex-cli
	
	# Windows
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/codex-cli
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-arm64.exe ./cmd/codex-cli

# Install the application
.PHONY: install
install:
	@echo "Installing CodexSentinel..."
	go install $(LDFLAGS) ./cmd/codex-cli

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run tests with race detection
.PHONY: test-race
test-race:
	@echo "Running tests with race detection..."
	go test -race -v ./...

# Run benchmarks
.PHONY: benchmark
benchmark:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Lint the code
.PHONY: lint
lint:
	@echo "Linting code..."
	golangci-lint run

# Format the code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Vet the code
.PHONY: vet
vet:
	@echo "Vetting code..."
	go vet ./...

# Generate documentation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	godoc -http=:6060

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	rm -f $(BINARY_NAME)

# Run the application
.PHONY: run
run: build
	@echo "Running CodexSentinel..."
	./$(BUILD_DIR)/$(BINARY_NAME)

# Show help
.PHONY: help
help:
	@echo "CodexSentinel Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  build          - Build the application"
	@echo "  build-all      - Build for multiple platforms"
	@echo "  install        - Install the application"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage"
	@echo "  test-race      - Run tests with race detection"
	@echo "  benchmark      - Run benchmarks"
	@echo "  lint           - Lint the code"
	@echo "  fmt            - Format the code"
	@echo "  vet            - Vet the code"
	@echo "  docs           - Generate documentation"
	@echo "  clean          - Clean build artifacts"
	@echo "  run            - Run the application"
	@echo "  help           - Show this help"

# Development targets
.PHONY: dev
dev: fmt lint test build

# Release preparation
.PHONY: release
release: clean fmt lint test build-all
	@echo "Release build complete. Binaries are in $(BUILD_DIR)/"

# Dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Update dependencies
.PHONY: deps-update
deps-update:
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

# Security audit
.PHONY: audit
audit:
	@echo "Running security audit..."
	go list -json -deps ./... | nancy sleuth

# Docker build
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t codexsentinel:$(VERSION) .
	docker tag codexsentinel:$(VERSION) codexsentinel:latest

# Docker run
.PHONY: docker-run
docker-run:
	@echo "Running Docker container..."
	docker run --rm -v $(PWD):/workspace codexsentinel:latest scan /workspace 