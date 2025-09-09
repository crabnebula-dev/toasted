.PHONY: all build release install clean test help

BINARY_NAME = toasted
CARGO = cargo
INSTALL_PATH = /usr/local/bin

all: build

build:
	@echo "Building debug version..."
	$(CARGO) build

release:
	@echo "Building optimized release version..."
	$(CARGO) build --release
	@echo "Binary available at: target/release/$(BINARY_NAME)"
	@ls -lh target/release/$(BINARY_NAME)

install: release
	@echo "Installing to $(INSTALL_PATH)..."
	@sudo cp target/release/$(BINARY_NAME) $(INSTALL_PATH)/
	@sudo chmod +x $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "Creating IOC directory..."
	@mkdir -p ~/.its-toasted/iocs
	@if [ -d iocs ]; then \
		cp -f iocs/*.yaml ~/.its-toasted/iocs/ 2>/dev/null || true; \
		echo "Installed default IOC files"; \
	fi
	@echo "Installed successfully!"
	@echo "IOC files can be placed in: ~/.its-toasted/iocs/"

test:
	@echo "Running tests..."
	$(CARGO) test --verbose

clean:
	@echo "Cleaning build artifacts..."
	$(CARGO) clean

help:
	@echo "Available targets:"
	@echo "  make build    - Build debug version"
	@echo "  make release  - Build release version"
	@echo "  make install  - Install to system"
	@echo "  make test     - Run tests"
	@echo "  make clean    - Clean build artifacts"
