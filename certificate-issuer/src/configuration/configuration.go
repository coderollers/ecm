package configuration

import "github.com/coderollers/go-utils"

type Configuration struct {
	Swagger CSwagger

	// Dependencies
	JaegerEndpoint     string
	VaultAddr          string
	VaultToken         string
	VaultAppRoleId     string
	VaultAppRoleSecret string
	VaultEngineName    string
	VaultStatePath     string

	// Configuration
	HttpPort    int32
	AcmeEmail   string
	StagingAcme bool

	// Internal settings
	CleanupTimeoutSec int32
	Environment       string
	UseTelemetry      string
	Development       bool
	GinLogger         bool
	UseSwagger        bool
	VaultLogging      bool
	Initialized       bool
}

var appConfig Configuration

func AppConfig() *Configuration {
	if appConfig.Initialized == false {
		loadEnvironmentVariables()
		appConfig.Initialized = true
	}
	return &appConfig
}

func loadEnvironmentVariables() {
	appConfig.JaegerEndpoint = utils.EnvOrDefault("JAEGER_ENDPOINT", "")
	appConfig.CleanupTimeoutSec = utils.EnvOrDefaultInt32("SHUTDOWN_TIMEOUT", 10)

	// vault variables
	appConfig.VaultAddr = utils.EnvOrDefault("VAULT_ADDR", "")
	appConfig.VaultToken = utils.EnvOrDefault("VAULT_TOKEN", "")
	appConfig.VaultAppRoleId = utils.EnvOrDefault("VAULT_APPROLE_ID", "")
	appConfig.VaultAppRoleSecret = utils.EnvOrDefault("VAULT_APPROLE_SECRET", "")
	appConfig.VaultEngineName = utils.EnvOrDefault("VAULT_ENGINE_NAME", "")
	appConfig.VaultStatePath = utils.EnvOrDefault("VAULT_STATE_PATH", "")

	// ACME
	appConfig.AcmeEmail = utils.EnvOrDefault("ACME_EMAIL", "")
}
