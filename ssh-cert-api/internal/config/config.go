package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level structure for the entire config.yaml file.
type Config struct {
	Groups           map[string]Group `yaml:"groups"`
	KeytabPath       string           `yaml:"keytab_path"`
	ServicePrincipal string           `yaml:"service_principal"`
	Listen           string           `yaml:"listen"`
	TlsCert          string           `yaml:"tls_cert"`
	TlsKey           string           `yaml:"tls_key"`
}

// Group defines a set of members and the certificate rules that apply to them.
type Group struct {
	Members          []string         `yaml:"members"`
	CertificateRules CertificateRules `yaml:"certificate_rules"`
}

// CertificateRules specifies the parameters for a signed SSH certificate.
type CertificateRules struct {
	Validity          string            `yaml:"validity"`
	AllowedPrincipals []string          `yaml:"allowed_principals"`
	Permissions       map[string]string `yaml:"permissions"`
	StaticAttributes  map[string]string `yaml:"static_attributes"`
	CriticalOptions   map[string]string `yaml:"critical_options"`
}

// LoadConfig reads the YAML file from the given path and unmarshals it.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file at %s: %w", path, err)
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	// Validate the loaded configuration to ensure it's usable.
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &cfg, nil
}

// Validate checks the configuration for logical errors after parsing.
func (c *Config) Validate() error {
	if len(c.Groups) == 0 {
		return fmt.Errorf("no groups defined in the configuration")
	}

	if c.KeytabPath == "" {
		return fmt.Errorf("keytab_path must be specified in the configuration")
	}

	if c.Listen == "" {
		c.Listen = ":8443"
	}

	if c.TlsCert == "" {
		c.TlsCert = "cert.pem"
	}
	if c.TlsKey == "" {
		c.TlsKey = "key.pem"
	}

	for name, group := range c.Groups {
		if len(group.Members) == 0 {
			return fmt.Errorf("group '%s' has no members", name)
		}

		rules := group.CertificateRules
		if rules.Validity == "" {
			return fmt.Errorf("group '%s' has no validity period defined", name)
		}

		// Try parsing the duration to catch errors early.
		_, err := time.ParseDuration(rules.Validity)
		if err != nil {
			return fmt.Errorf("invalid validity duration for group '%s': %w", name, err)
		}

		if len(rules.AllowedPrincipals) == 0 {
			return fmt.Errorf("group '%s' has no allowed_principals", name)
		}
	}
	return nil
}
