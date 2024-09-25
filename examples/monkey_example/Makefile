.PHONY: all run clean

all: build execute

build:
	@echo "Building the project..."
	@go build -gcflags=all=-l -o main

execute: build
	@echo "Running in execution mode with cap locking enabled..."
	@./main

clean:
	@echo "Cleaning up..."
	@rm -f main
