# VouSSH Makefile

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

# Binary names
BINARY_SERVER=voussh
BINARY_CLIENT=vsh

# Build directories
CMD_SERVER=./cmd/voussh
CMD_CLIENT=./cmd/vsh

# Build flags for static linking (for NixOS compatibility)
LDFLAGS=-ldflags="-s -w -extldflags '-static'"
CGO_ENABLED=0

.PHONY: all build clean test help

# Default target
all: build

# Build both binaries
build: build-server build-client
	@echo "✓ Build complete"

# Build server binary
build-server:
	@echo "Building $(BINARY_SERVER)..."
	@CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) $(LDFLAGS) -o $(BINARY_SERVER) $(CMD_SERVER)

# Build client binary
build-client:
	@echo "Building $(BINARY_CLIENT)..."
	@CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) $(LDFLAGS) -o $(BINARY_CLIENT) $(CMD_CLIENT)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@$(GOCLEAN)
	@rm -f $(BINARY_SERVER) $(BINARY_CLIENT)
	@echo "✓ Clean complete"

# Run tests
test:
	@echo "Running tests..."
	@$(GOTEST) -v ./...

# Install binaries to /usr/local/bin (requires sudo)
install: build
	@echo "Installing binaries to /usr/local/bin..."
	@sudo cp $(BINARY_SERVER) /usr/local/bin/
	@sudo cp $(BINARY_CLIENT) /usr/local/bin/
	@echo "✓ Installation complete"

# Uninstall binaries from /usr/local/bin (requires sudo)
uninstall:
	@echo "Removing binaries from /usr/local/bin..."
	@sudo rm -f /usr/local/bin/$(BINARY_SERVER)
	@sudo rm -f /usr/local/bin/$(BINARY_CLIENT)
	@echo "✓ Uninstall complete"

# Build for multiple platforms
build-all: build-linux build-darwin build-windows
	@echo "✓ All platforms built"

# Linux builds
build-linux:
	@echo "Building for Linux..."
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_SERVER)-linux-amd64 $(CMD_SERVER)
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_CLIENT)-linux-amd64 $(CMD_CLIENT)
	@GOOS=linux GOARCH=arm64 CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_SERVER)-linux-arm64 $(CMD_SERVER)
	@GOOS=linux GOARCH=arm64 CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_CLIENT)-linux-arm64 $(CMD_CLIENT)

# macOS builds
build-darwin:
	@echo "Building for macOS..."
	@GOOS=darwin GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_SERVER)-darwin-amd64 $(CMD_SERVER)
	@GOOS=darwin GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_CLIENT)-darwin-amd64 $(CMD_CLIENT)
	@GOOS=darwin GOARCH=arm64 CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_SERVER)-darwin-arm64 $(CMD_SERVER)
	@GOOS=darwin GOARCH=arm64 CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_CLIENT)-darwin-arm64 $(CMD_CLIENT)

# Windows builds
build-windows:
	@echo "Building for Windows..."
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_SERVER)-windows-amd64.exe $(CMD_SERVER)
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_CLIENT)-windows-amd64.exe $(CMD_CLIENT)

# Run the server locally
run-server: build-server
	@echo "Starting $(BINARY_SERVER)..."
	@./$(BINARY_SERVER)

# Initialize CA keys
init:
	@echo "Initializing CA keys..."
	@./$(BINARY_SERVER) init

# Show help
help:
	@echo "VouSSH Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make              Build both server and client binaries"
	@echo "  make build        Build both server and client binaries"
	@echo "  make build-server Build only the server binary"
	@echo "  make build-client Build only the client binary"
	@echo "  make clean        Remove built binaries"
	@echo "  make test         Run tests"
	@echo "  make install      Install binaries to /usr/local/bin (requires sudo)"
	@echo "  make uninstall    Remove binaries from /usr/local/bin (requires sudo)"
	@echo "  make build-all    Build for all platforms (linux, darwin, windows)"
	@echo "  make run-server   Build and run the server"
	@echo "  make init         Initialize CA keys"
	@echo "  make help         Show this help message"