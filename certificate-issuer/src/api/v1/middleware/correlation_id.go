package middleware

import (
	"certificate-issuer/configuration"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func CorrelationId() gin.HandlerFunc {
	return func(c *gin.Context) {
		var correlationId string
		if correlationId = c.Request.Header.Get(configuration.CorrelationIdHeaderKey); correlationId == "" {
			correlationId = uuid.New().String()
		}
		c.Set(configuration.CorrelationIdKey, correlationId)
		c.Next()
	}
}
