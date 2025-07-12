package main

import (
	"fmt"
	"log"
)

// EntropyTest demonstrates high entropy strings that might be secrets
func EntropyTest() {
	// High entropy strings (likely secrets)
	apiKey := "sk-1234567890abcdef1234567890abcdef1234567890abcdef"
	password := "P@ssw0rd!2023#Secure$Complex%String"
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	
	// Database connection strings
	dbURL := "postgresql://user:password123@localhost:5432/mydb"
	mongoURL := "mongodb://user:password123@localhost:27017/mydb"
	
	// AWS credentials
	awsAccessKey := "AKIAIOSFODNN7EXAMPLE"
	awsSecretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	
	// SSH private key (partial)
	sshKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
	
	// Log the secrets (this would be flagged)
	log.Printf("API Key: %s", apiKey)
	log.Printf("Password: %s", password)
	log.Printf("Token: %s", token)
	log.Printf("DB URL: %s", dbURL)
	log.Printf("Mongo URL: %s", mongoURL)
	log.Printf("AWS Access Key: %s", awsAccessKey)
	log.Printf("AWS Secret Key: %s", awsSecretKey)
	log.Printf("SSH Key: %s", sshKey)
	
	fmt.Println("High entropy strings detected")
}

// HardcodedSecrets demonstrates hardcoded secrets in code
func HardcodedSecrets() {
	// These would be flagged by entropy scanners
	config := map[string]string{
		"database_password": "MySecurePassword123!",
		"api_secret":        "sk-9876543210fedcba9876543210fedcba9876543210fedcba",
		"jwt_secret":        "my-super-secret-jwt-key-2023",
		"encryption_key":    "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef",
	}
	
	for key, value := range config {
		fmt.Printf("%s: %s\n", key, value)
	}
}

// EntropyDetection demonstrates entropy-based detection
func EntropyDetection() {
	// High entropy strings that should be detected
	highEntropyStrings := []string{
		"sk-1234567890abcdef1234567890abcdef1234567890abcdef",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"-----BEGIN RSA PRIVATE KEY-----",
	}
	
	fmt.Println("High entropy strings that should be detected:")
	for _, str := range highEntropyStrings {
		fmt.Printf("- %s\n", str)
	}
} 