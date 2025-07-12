package main

import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"log"
)

// VulnerableDependencies demonstrates packages with known vulnerabilities
func VulnerableDependencies() {
	// Weak cryptographic algorithms
	hash := md5.Sum([]byte("password"))
	_ = hash
	
	sha1Hash := sha1.Sum([]byte("password"))
	_ = sha1Hash
	
	fmt.Println("Using weak cryptographic algorithms")
}

// OutdatedDependencies demonstrates outdated packages
func OutdatedDependencies() {
	// These would be flagged by vulnerability scanners
	log.Println("Checking for outdated dependencies...")
	
	// Simulate finding vulnerable packages
	fmt.Println("Found package with known CVE: CVE-2023-1234")
	fmt.Println("Found package with known CVE: CVE-2023-5678")
	fmt.Println("Found package with known CVE: CVE-2023-9012")
	
	// Simulate finding outdated packages
	fmt.Println("Found package with outdated version")
	fmt.Println("Found package with security vulnerabilities")
}

// DependencyAudit demonstrates dependency auditing
func DependencyAudit() {
	// Check for vulnerable dependencies
	vulnerabilities := []string{
		"CVE-2023-1234: SQL injection in database driver",
		"CVE-2023-5678: XSS in web framework",
		"CVE-2023-9012: RCE in crypto library",
	}
	
	fmt.Println("Dependency audit results:")
	for _, vuln := range vulnerabilities {
		fmt.Printf("- %s\n", vuln)
	}
	
	// Simulate severity levels
	fmt.Println("High severity vulnerabilities: 3")
	fmt.Println("Medium severity vulnerabilities: 2")
	fmt.Println("Low severity vulnerabilities: 1")
} 