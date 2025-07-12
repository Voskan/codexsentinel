package main

import (
	"fmt"
	"log"
)

// LicenseTest demonstrates packages with different license types
func LicenseTest() {
	// MIT License (safe)
	fmt.Println("MIT licensed packages are generally safe")
	
	// Apache 2.0 (safe)
	fmt.Println("Apache 2.0 licensed packages are generally safe")
	
	// GPL v3 (potentially problematic)
	fmt.Println("GPL v3 packages may have copyleft requirements")
	
	// AGPL v3 (potentially problematic)
	fmt.Println("AGPL v3 packages have strong copyleft requirements")
	
	// Proprietary (potentially problematic)
	fmt.Println("Proprietary packages may have usage restrictions")
}

// ProblematicLicenses demonstrates potentially problematic license scenarios
func ProblematicLicenses() {
	// These would be flagged by license scanners
	log.Println("Checking for problematic licenses...")
	
	// Simulate finding GPL packages
	fmt.Println("Found package with GPL v3 license")
	
	// Simulate finding AGPL packages  
	fmt.Println("Found package with AGPL v3 license")
	
	// Simulate finding proprietary packages
	fmt.Println("Found package with proprietary license")
}

// LicenseCompliance demonstrates license compliance checking
func LicenseCompliance() {
	// Check if we're compliant with our license policy
	allowedLicenses := []string{"MIT", "Apache-2.0", "BSD-3-Clause"}
	deniedLicenses := []string{"GPL-3.0", "AGPL-3.0", "Proprietary"}
	
	fmt.Printf("Allowed licenses: %v\n", allowedLicenses)
	fmt.Printf("Denied licenses: %v\n", deniedLicenses)
	
	// Simulate license check results
	fmt.Println("License compliance check completed")
} 