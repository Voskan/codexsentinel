package main

import (
	"fmt"
	"os/exec"
)

// DEMO: This function should trigger command injection detection
func vulnerableCommandExecution(userInput string) {
	// This should be detected as vulnerable
	exec.Command("sh", "-c", userInput)
}

// DEMO: This function should trigger SQL injection detection  
func vulnerableSQLQuery(userID string) {
	// This should be detected as vulnerable
	query := "SELECT * FROM users WHERE id = " + userID
	fmt.Println(query)
}

// DEMO: This function should trigger XSS detection
func vulnerableHTMLOutput(userInput string) {
	// This should be detected as vulnerable
	html := "<h1>Hello, " + userInput + "!</h1>"
	fmt.Println(html)
}

// DEMO: Safe function for comparison
func safeFunction(userInput string) {
	// This should NOT be detected
	fmt.Println("Safe output:", userInput)
} 