package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const Version = "0.1.0"

type Config struct {
	Listen         string
	DatabasePath   string
	Certificate    string
	PrivateKey     string
	Shell          string
	SessionIdle    time.Duration
	SessionMax     time.Duration
	InviteLifetime time.Duration
	AuditRetention time.Duration
	AuditMaxEvents int
	MaxTerminals   int
}

func Default() (Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Config{}, fmt.Errorf("resolve home directory: %w", err)
	}
	dataDir := filepath.Join(home, ".local", "share", "web-ssh")
	configDir := filepath.Join(home, ".config", "web-ssh")
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}
	return Config{
		Listen:         "0.0.0.0:8443",
		DatabasePath:   filepath.Join(dataDir, "web-ssh.db"),
		Certificate:    filepath.Join(configDir, "cert.pem"),
		PrivateKey:     filepath.Join(configDir, "key.pem"),
		Shell:          shell,
		SessionIdle:    30 * time.Minute,
		SessionMax:     12 * time.Hour,
		InviteLifetime: 24 * time.Hour,
		AuditRetention: 90 * 24 * time.Hour,
		AuditMaxEvents: 100_000,
		MaxTerminals:   2,
	}, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Listen) == "" {
		return fmt.Errorf("listen address is required")
	}
	if c.DatabasePath == "" {
		return fmt.Errorf("database path is required")
	}
	if c.Certificate == "" || c.PrivateKey == "" {
		return fmt.Errorf("certificate and private key are required")
	}
	if c.Shell == "" || !filepath.IsAbs(c.Shell) {
		return fmt.Errorf("shell must be an absolute path")
	}
	if c.SessionIdle <= 0 || c.SessionMax < c.SessionIdle {
		return fmt.Errorf("session expiry values are invalid")
	}
	if c.MaxTerminals < 1 || c.MaxTerminals > 16 {
		return fmt.Errorf("max terminals must be between 1 and 16")
	}
	return nil
}

func EnvironmentOverrides(config *Config) error {
	if value := os.Getenv("WEB_SSH_LISTEN"); value != "" {
		config.Listen = value
	}
	if value := os.Getenv("WEB_SSH_DATABASE"); value != "" {
		config.DatabasePath = value
	}
	if value := os.Getenv("WEB_SSH_CERT"); value != "" {
		config.Certificate = value
	}
	if value := os.Getenv("WEB_SSH_KEY"); value != "" {
		config.PrivateKey = value
	}
	if value := os.Getenv("WEB_SSH_SHELL"); value != "" {
		config.Shell = value
	}
	if value := os.Getenv("WEB_SSH_MAX_TERMINALS"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("parse WEB_SSH_MAX_TERMINALS: %w", err)
		}
		config.MaxTerminals = parsed
	}
	return config.Validate()
}
