package config

import (
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	// Output settings
	OutputFormat string `mapstructure:"output"`
	OutputFile   string `mapstructure:"output-file"`
	Verbose      bool   `mapstructure:"verbose"`

	// Concurrency settings
	Concurrency int `mapstructure:"concurrency"`

	// Scan settings
	SkipNuclei bool     `mapstructure:"skip-nuclei"`
	SkipPorts  bool     `mapstructure:"skip-ports"`
	SkipDirs   bool     `mapstructure:"skip-dirs"`
	Ports      []string `mapstructure:"ports"`

	// Server settings
	ServerAddr string `mapstructure:"addr"`

	// Paths (for container)
	WordlistPath  string `mapstructure:"wordlist-path"`
	TemplatesPath string `mapstructure:"templates-path"`
}

func Load() (*Config, error) {
	cfg := &Config{
		OutputFormat:  "json",
		Concurrency:   10,
		Ports:         []string{"21", "22", "23", "25", "53", "80", "110", "143", "443", "3306", "3389", "5432", "6379", "8000", "8080", "8443"},
		ServerAddr:    ":8080",
		WordlistPath:  "/app/wordlists/quickhits.txt",
		TemplatesPath: "/app/nuclei-templates",
	}

	if err := viper.Unmarshal(cfg); err != nil {
		return nil, err
	}

	// Heroku sets PORT env var - override ServerAddr if present
	if port := os.Getenv("PORT"); port != "" {
		cfg.ServerAddr = ":" + port
	}

	return cfg, nil
}
