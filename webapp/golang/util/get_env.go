package util

import (
	"os"
	"strconv"
)

func GetEnv(key, val string) string {
	if v := os.Getenv(key); v == "" {
		return val
	} else {
		return v
	}
}

func GetEnvInt(key string, defaultVal int) int {
	envVal, err := strconv.Atoi(GetEnv(key, strconv.Itoa(defaultVal)))
	if err != nil {
		return defaultVal
	}
	return envVal
}
