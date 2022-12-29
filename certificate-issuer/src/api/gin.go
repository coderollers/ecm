package api

import (
	"certificate-issuer/api/v1/handlers"
	"context"
	"fmt"
	"net/http"

	"certificate-issuer/api/v1/middleware"
	"certificate-issuer/configuration"

	"github.com/coderollers/go-logger"
	"github.com/coderollers/go-stats/concurrency"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

func StartGin(ctx context.Context) {
	defer concurrency.GlobalWaitGroup.Done()

	conf := configuration.AppConfig()
	log := logger.SugaredLogger()

	// Set up gin
	log.Debugf("setting up gin")
	if !conf.GinLogger {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.New()

	// Set up the middleware
	if conf.GinLogger {
		log.Warnf("Gin's logger is active! Logs will be unstructured!")
		router.Use(gin.Logger())
	}
	router.Use(otelgin.Middleware(configuration.OTName))
	router.Use(gin.Recovery())
	router.Use(middleware.CorrelationId())
	router.Use(middleware.Vault())

	// Set up the groups
	userAPI := router.Group("/v1")
	{
		userAPI.POST("/certificate", handlers.CertificatePost)
		userAPI.GET("/renew", handlers.RenewGet)
		userAPI.GET("/renew/:name", handlers.RenewGet)
	}

	// Activate swagger if configured
	if conf.UseSwagger {
		log.Infof("swagger is active, enabling endpoints")
		url := ginSwagger.URL("/swagger/doc.json") // The url pointing to API definition
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, url))
	}

	// Set up the listener
	httpSrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", conf.HttpPort),
		Handler: router,
	}

	// Start the HTTP Server
	go func() {
		log.Infof("listening on port %d", conf.HttpPort)
		if err := httpSrv.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Fatalf("unrecoverable HTTP Server failure: %s", err.Error())
			}
		}
	}()

	// Block until SIGTERM/SIGINT
	<-ctx.Done()

	// Clean up and shutdown the HTTP server
	log.Infof("attempting to shutdown the HTTP server")
	if err := httpSrv.Shutdown(context.Background()); err != nil {
		log.Errorf("HTTP server failed to shutdown gracefully: %s", err.Error())
	} else {
		log.Infof("HTTP Server was shutdown successfully")
	}
}
