package stackanalyzer

import (
	"testing"
)

func TestLoadModuleCache_CanParseRequireInGoMod(t *testing.T) {
	// arrange
	var modManifest string = "../../testdata/go.mod"

	// act
	err := LoadModuleCache(modManifest)
	if err != nil {
		t.Errorf("Error initalising module cache: %v", err)
	}

	// assert
	if len(ImportedPackagesCache.packages) != 1 {
		t.Errorf("Expected 1 module, got %d", len(ImportedPackagesCache.packages))
	}
	if ImportedPackagesCache.packages[0] != "example.com" {
		t.Errorf("Expected module to be example.com, got %s", ImportedPackagesCache.packages[0])
	}
}

func TestGetCallerPackageAndFunction_GetCallerAndPackageInformationFromBasiccgo(t *testing.T) {
	// arrange
	var stackFrame = "example.com/filereader.ExecuteMaliciousCGO"
	var modManifest string = "../../testdata/go.mod"

	// act
	// this is to load the module cache
	err := LoadModuleCache(modManifest)
	if err != nil {
		t.Errorf("Error initalising module cache: %v", err)
	}
	callerPackage, callerFunction, err := GetCallerPackageAndFunction(stackFrame)

	// assert
	if err != nil {
		t.Errorf("Error getting caller package and function: %v", err)
	}

	if callerPackage != "example.com/filereader" {
		t.Errorf("Expected caller package to be example.com/filereader, got %s", callerPackage)
	}
	if callerFunction != "example.com/filereader.ExecuteMaliciousCGO" {
		t.Errorf("Expected caller function to be ExecuteMaliciousCGO, got %s", callerFunction)
	}
}
