package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type ConfigFile struct {
	Targets struct {
		Binaries    []string `toml:"binaries"`
		BinaryPaths []string `toml:"binary_paths"`
	} `toml:"targets"`
}

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <config.toml> <output_header.h>", os.Args[0])
	}

	configPath := os.Args[1]
	outputPath := os.Args[2]

	binaryPaths := processConfig(configPath, outputPath)
	fmt.Println(strings.Join(binaryPaths, ","))
}

func processConfig(configPath, outputPath string) []string {
	var configFile ConfigFile
	if _, err := toml.DecodeFile(configPath, &configFile); err != nil {
		log.Fatalf("Error reading config.toml: %v", err)
	}

	// Create the include directory if it doesn't exist
	includeDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(includeDir, 0755); err != nil {
		log.Fatalf("Error creating include directory: %v", err)
	}

	// Generate the header file
	targetNames := strings.Join(configFile.Targets.Binaries, `","`)
	headerContent := fmt.Sprintf(`#define TARGET_PROCESS_NAMES {"%s"}`, targetNames)

	if err := os.WriteFile(outputPath, []byte(headerContent), 0644); err != nil {
		log.Fatalf("Error writing to %s: %v", outputPath, err)
	}

	log.Printf("Generated %s with target process names: %v", outputPath, configFile.Targets.Binaries)

	// Return the list of binaries for further use
	return configFile.Targets.BinaryPaths
}
