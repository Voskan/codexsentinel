package testdata

import (
	"fmt"
)

// Глобальные переменные для тестирования AST Walker
var GlobalConfig = "test-config"
var GlobalSecret = "secret-key-123"
var GlobalCounter = 0
var GlobalFlag = true

// Константы тоже считаются глобальными
const (
	MaxRetries = 3
	Timeout    = 30
	DebugMode  = true
)

// Глобальная структура
var GlobalSettings = struct {
	Host string
	Port int
}{
	Host: "localhost",
	Port: 8080,
}

// Функция с глобальными переменными
func ProcessGlobalData() {
	// Использование глобальных переменных
	fmt.Printf("Config: %s\n", GlobalConfig)
	fmt.Printf("Counter: %d\n", GlobalCounter)
	
	// Увеличение глобального счетчика
	GlobalCounter++
	
	// Проверка глобального флага
	if GlobalFlag {
		fmt.Println("Debug mode is enabled")
	}
}

// Еще одна функция с глобальными переменными
func UpdateGlobalSettings() {
	// Изменение глобальных настроек
	GlobalSettings.Host = "example.com"
	GlobalSettings.Port = 443
	
	// Использование глобальной константы
	for i := 0; i < MaxRetries; i++ {
		fmt.Printf("Retry attempt %d\n", i+1)
	}
}

// Функция с потенциально опасными глобальными переменными
func DangerousGlobalUsage() {
	// Использование глобального секрета (потенциально опасно)
	apiKey := GlobalSecret
	fmt.Printf("Using API key: %s\n", apiKey)
	
	// Использование глобального флага для контроля безопасности
	if !GlobalFlag {
		fmt.Println("Security mode disabled")
	}
} 