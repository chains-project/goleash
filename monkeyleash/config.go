package monkeyleash

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"bou.ke/monkey"
)

type ConfigCaps struct {
	Allowlists map[string][]string `json:"allowlists"`
	Hashes     map[string][]string `json:"hashes"`
}

type Config struct {
	configCaps     ConfigCaps
	capFuncMapping map[string]string
	isHashMode     bool
}

func LoadConfig(capsFile, interestingFile string) (*Config, error) {

	config := &Config{}

	config.configCaps = loadConfigCaps(capsFile)

	var err error
	config.capFuncMapping, err = loadCapFuncMapping(interestingFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load CapFuncMapping: %v", err)
	}

	config.isHashMode = os.Getenv("GOCAP_HASH_MODE") == "true"

	return config, nil
}

func loadConfigCaps(capsFile string) ConfigCaps {
	var configCaps ConfigCaps

	file, err := os.Open(capsFile)
	if err != nil {
		fmt.Printf("Error opening caps file: %v\n", err)
		return configCaps
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&configCaps)
	if err != nil {
		fmt.Printf("Error decoding JSON: %v\n", err)
	}

	return configCaps
}

func loadCapFuncMapping(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	funcCapMap := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "func ") {
			parts := strings.Fields(line)
			if len(parts) == 3 {
				funcCapMap[parts[1]] = parts[2]
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return funcCapMap, nil
}

func writeConfigFile(filename string, configCaps ConfigCaps) {
	jsonData, err := json.MarshalIndent(configCaps, "", "    ")
	if err == nil {
		monkey.Unpatch(os.WriteFile)
		os.WriteFile(filename, jsonData, 0644)
		monkey.Patch(os.WriteFile, WriteFileReplaceHash)
	}
}
