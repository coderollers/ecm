package configuration

// Correlation ID related constants

const (
	CorrelationIdKey       = "correlation_id"
	CorrelationIdHeaderKey = "X-Correlation-ID"
)

// Constants used in Middleware

const (
	VaultContextKey = "vault"
)

// Constants used by secrets

const (
	VaultStateAcmeUserSubPath                  = "acme_user"
	VaultStateCertificatesSubPath              = "certificates"
	VaultStateCertificateConfigurationsSubPath = "certificate_configurations"
)

// Telemetry related constants

const (
	OTName    = "certificate-issuer"
	OTVersion = "1.0"
	OTSchema  = "/api/v1"
)
