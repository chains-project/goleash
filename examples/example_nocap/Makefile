.PHONY: all generate build run benchmark clean

all: generate build execute
all-hash: generate build hash
all-bench: generate build benchmark

generate:
	@echo "Running go generate..."
	@go generate ./...

build: generate
	@echo "Building the project..."
	@go build -gcflags=all=-l -o main

hash: build
	@echo "Running in configuration mode to generate stack hashes..."
	@GOCAP_HASH_MODE=true ./main

execute: build
	@echo "Running in execution mode with cap locking enabled..."
	@GOCAP_HASH_MODE=false ./main

benchmark: build
	@echo "Running the executable with benchmark flag..."
	@./main -benchmark

clean:
	@echo "Cleaning up..."
	@rm -f main
	@rm -f hashes.cap
	@rm -f *.txt *.pdf
