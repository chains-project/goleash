package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func StartTracer(args []string, buffer *bytes.Buffer) (*exec.Cmd, error) {
	tracer := exec.Command(args[0], args[1:]...)

	tracer.Stdout = buffer
	tracer.Stderr = buffer

	// Run the command in a goroutine
	go func() {
		err := tracer.Run()
		if err != nil {
			fmt.Printf("Error running tracer: %v\n", buffer.String())
		}
	}()

	return tracer, nil
}

func StopTracer(cmd *exec.Cmd) error {
	if cmd.Process != nil {
		err := cmd.Process.Kill()
		if err != nil {
			return fmt.Errorf("failed to stop process: %v", err)
		}
	}
	return nil
}

func TestBuild(t *testing.T) {
	var outputBuffer bytes.Buffer
	tracer, err := StartTracer([]string{"./bpf_loader", "-binary", "../testpkgs/basiccgo/basiccgo", "-mode", "build", "-mod-manifest", "../testpkgs/basiccgo/go.mod"}, &outputBuffer)
	if err != nil {
		t.Errorf("Error starting process: %v", err)
	}

	time.Sleep(2 * time.Second)

	exec.Command("../testpkgs/basiccgo/basiccgo").Run()
	if err != nil {
		t.Errorf("Error running basiccgo: %v", err)
	}

	StopTracer(tracer)

	var expectedCallerFunction = "Go caller function: example.com/filereader.ExecuteMaliciousCGO"
	var expectedCallerPackage = "Go caller package: example.com/filereader"
	var actualOutput = outputBuffer.String()

	if !strings.Contains(actualOutput, expectedCallerFunction) {
		t.Errorf("Expected output to contain %s, got %s", expectedCallerFunction, actualOutput)
	}

	if !strings.Contains(actualOutput, expectedCallerPackage) {
		t.Errorf("Expected output to contain %s, got %s", expectedCallerPackage, actualOutput)
	}
}
