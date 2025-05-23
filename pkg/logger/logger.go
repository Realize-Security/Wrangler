package logger

import (
	"log"
)

// Printf wraps log.Printf to ensure all output goes through the logger
func Printf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

// Println wraps log.Println
func Println(v ...interface{}) {
	log.Println(v...)
}

// Fatalf wraps log.Fatalf
func Fatalf(format string, v ...interface{}) {
	log.Fatalf(format, v...)
}

// Errorf logs an error message
func Errorf(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
}

// Warnf logs a warning message
func Warnf(format string, v ...interface{}) {
	log.Printf("[WARN] "+format, v...)
}

// Infof logs an info message
func Infof(format string, v ...interface{}) {
	log.Printf("[INFO] "+format, v...)
}

// Debugf logs a debug message (you can add a debug flag to control this)
func Debugf(format string, v ...interface{}) {
	log.Printf("[DEBUG] "+format, v...)
}

// DebugEnabled can be set based on CLI flags
var DebugEnabled bool

// DebugIfEnabled only logs if debugging is enabled
func DebugIfEnabled(format string, v ...interface{}) {
	if DebugEnabled {
		Debugf(format, v...)
	}
}

// Standardize fmt.Print* calls to use the logger
// This ensures all output is captured in the log file

// Print wraps fmt.Print but directs to logger
func Print(v ...interface{}) {
	log.Print(v...)
}

// PrintfCompat provides log.Printf compatibility but uses the logger
func PrintfCompat(format string, v ...interface{}) {
	// Remove trailing newline if present since log.Printf adds one
	if len(format) > 0 && format[len(format)-1] == '\n' {
		format = format[:len(format)-1]
	}
	log.Printf(format, v...)
}
