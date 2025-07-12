package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

// BAD: Command injection via user input
func handleUserCommand(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("cmd")
	
	// VULNERABILITY: User input used directly in exec.Command
	cmd := exec.Command("sh", "-c", userInput)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Command failed", 500)
		return
	}
	
	fmt.Fprintf(w, "Output: %s", output)
}

// BAD: Another command injection example
func processFile(filename string) error {
	// VULNERABILITY: Filename from user input used in command
	cmd := exec.Command("cat", filename)
	return cmd.Run()
}

// BAD: Command injection with os.Getenv
func runSystemCommand() {
	envVar := os.Getenv("USER_COMMAND")
	// VULNERABILITY: Environment variable used in command
	exec.Command("bash", "-c", envVar).Run()
}

// GOOD: Safe command execution
func safeCommandExecution(command string) {
	// Safe: Only allow specific commands
	allowedCommands := map[string]bool{
		"ls": true,
		"pwd": true,
	}
	
	if allowedCommands[command] {
		exec.Command(command).Run()
	}
} 