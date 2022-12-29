package middleware

import (
	"certificate-issuer/configuration"

	"github.com/coderollers/go-logger"
	"github.com/gin-gonic/gin"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"go.uber.org/zap"
)

func Vault() gin.HandlerFunc {
	return func(c *gin.Context) {
		var (
			err       error
			client    *api.Client
			appConfig = configuration.AppConfig()
			log       = logger.SugaredLogger().With("package", "middleware", "action", "Vault")
		)

		vaultConfig := api.DefaultConfig()
		vaultConfig.Address = appConfig.VaultAddr
		vaultConfig.MaxRetries = 10

		if appConfig.VaultLogging {
			vaultConfig.Logger = &VaultLogger{Log: log}
		}

		client, err = api.NewClient(vaultConfig)

		if appConfig.VaultToken != "" {
			log.Debugf("vault token detected, using it (would take precedence over approle)")
			client.SetToken(appConfig.VaultToken)
		} else {
			var (
				appRoleAuth *approle.AppRoleAuth
				authInfo    *api.Secret
			)
			log.Debugf("vault approle detected, using it")
			// TODO: #168 Implement wrapped secret and trusted orchestrator
			secretId := &approle.SecretID{FromString: appConfig.VaultAppRoleSecret}
			appRoleAuth, err = approle.NewAppRoleAuth(appConfig.VaultAppRoleId, secretId)
			if err != nil {
				log.Errorf("error in approle auth: %s", err.Error())
				c.AbortWithStatusJSON(403, struct{ Error error }{Error: err})
				return
			}
			authInfo, err = client.Auth().Login(c.Request.Context(), appRoleAuth)
			if err != nil {
				log.Errorf("error during approle login: %s", err.Error())
				c.AbortWithStatusJSON(403, struct{ Error error }{Error: err})
				return
			}
			if authInfo == nil {
				log.Errorf("no approle info was returned after login")
				c.AbortWithStatusJSON(403, struct{ Error error }{Error: err})
				return
			}
		}
		log.Debugf("vault client created successfully")

		c.Set(configuration.VaultContextKey, client)
		c.Next()
	}
}

type VaultLogger struct {
	Log *zap.SugaredLogger
}

func (vl *VaultLogger) Debug(fmt string, args ...interface{}) {
	vl.Log.Debugf(fmt, args)
}

func (vl *VaultLogger) Info(fmt string, args ...interface{}) {
	vl.Log.Infof(fmt, args)
}

func (vl *VaultLogger) Warn(fmt string, args ...interface{}) {
	vl.Log.Warnf(fmt, args)
}

func (vl *VaultLogger) Error(fmt string, args ...interface{}) {
	vl.Log.Errorf(fmt, args)
}
