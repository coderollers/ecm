package handlers

import (
	"certificate-issuer/configuration"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// tracer init
var tracer = otel.Tracer("API", trace.WithInstrumentationVersion(configuration.OTVersion), trace.WithSchemaURL(configuration.OTSchema))
