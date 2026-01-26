package logger

import "os"

func init() {
	// Override the placeholder function with the real implementation
	getEnvFunc = os.Getenv
}
