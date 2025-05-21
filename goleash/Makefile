.PHONY: all clean build cap-enforce sys-enforce generate-config

# Variables
CONFIG_FILE := config.toml
HEADER_FILE := include/target_names.h
BPF_LOADER := bpf_loader
BINARIES := $(shell go run scripts/read_config.go $(CONFIG_FILE) $(HEADER_FILE))

# Default target
all: generate-config $(BPF_LOADER)

# Read binaries from config.toml
generate-config:
	@echo "Processing $(CONFIG_FILE) to generate $(HEADER_FILE)..."
	@mkdir -p $(dir $(HEADER_FILE))
	@go run scripts/read_config.go $(CONFIG_FILE) $(HEADER_FILE)

# Build the bpf_loader binary
$(BPF_LOADER): main.go
	@echo "Building $(BPF_LOADER)..."
	go generate
	go build -o $(BPF_LOADER)

# Build modes
build: all
	sudo ./$(BPF_LOADER) -binary "$(BINARIES)" -mode build

cap-enforce: all
	sudo ./$(BPF_LOADER) -binary "$(BINARIES)" -mode cap-enforce

sys-enforce: all
	sudo ./$(BPF_LOADER) -binary "$(BINARIES)" -mode sys-enforce

# Clean up generated files
clean:
	@echo "Cleaning up..."
	rm -f $(HEADER_FILE) $(BPF_LOADER)
	rm -rf *.o ebpf_*