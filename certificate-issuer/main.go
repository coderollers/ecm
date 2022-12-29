package main

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"certificate-issuer/api"
	"certificate-issuer/configuration"
	"certificate-issuer/docs"

	"github.com/coderollers/go-logger"
	"github.com/coderollers/go-stats/concurrency"
	"github.com/coderollers/go-utils"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel/sdk/trace"
)

func main() {
	var (
		ctx    context.Context
		cancel context.CancelFunc
		tp     *trace.TracerProvider
		err    error
	)

	// Initialize configuration
	appConfig := configuration.AppConfig()

	// Configure command-line parameters
	pflag.StringVarP(&appConfig.UseTelemetry, "telemetry", "r", "", "Activate telemetry. Possible values: local or remote")
	pflag.Int32VarP(&appConfig.CleanupTimeoutSec, "timeout", "t", 30, "Time to wait for graceful shutdown on SIGTERM/SIGINT in seconds. Default: 30")
	pflag.Int32VarP(&appConfig.HttpPort, "port", "p", 8080, "TCP port for the HTTP listener to bind to. Default: 8080")
	pflag.BoolVarP(&appConfig.UseSwagger, "swagger", "s", false, "Activate swagger. Do not use this in Production!")
	pflag.BoolVarP(&appConfig.Development, "devel", "d", false, "Start in development mode. Implies --swagger. Do not use this in Production!")
	pflag.BoolVarP(&appConfig.StagingAcme, "staging", "x", false, "Use the Staging ACME environment for testing. Do not use this in Production!")
	pflag.BoolVarP(&appConfig.VaultLogging, "vault-logging", "v", false, "Configure the Vault API Client internal logger. Do not use this in Production!")
	pflag.BoolVarP(&appConfig.GinLogger, "gin-logger", "g", false, "Activate Gin's logger, for debugging. Do not use this in Production!")
	pflag.Parse()

	// Initialize main context and set up cancellation token for SIGINT/SIGQUIT
	ctx = context.Background()
	ctx, cancel = context.WithCancel(ctx)
	cSignal := make(chan os.Signal)
	signal.Notify(cSignal, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Initialize logger
	logger.Init(ctx, false, appConfig.Development)
	logger.SetCorrelationIdFieldKey(configuration.CorrelationIdKey)
	logger.SetCorrelationIdContextKey(configuration.CorrelationIdKey)
	log := logger.SugaredLogger()
	//goland:noinspection GoUnhandledErrorResult
	defer log.Sync()
	defer logger.PanicLogger()

	// Sanity checks
	if !appConfig.Development {
		if appConfig.VaultLogging {
			log.Warnf("Vault logging cannot be enabled in production mode!")
			appConfig.VaultLogging = false
		}
	} else {
		appConfig.UseSwagger = true
	}

	if appConfig.UseSwagger {
		docs.SwaggerInfo.Title = "certificate-issuer"
		docs.SwaggerInfo.Version = "1.0"
		docs.SwaggerInfo.BasePath = "/"
		docs.SwaggerInfo.Description = "ECM Certificate Issuer"
	}
	log.Infof(docs.SwaggerInfo.BasePath)

	if port, cloud, err := utils.GetFunctionListeningPort(); err != nil {
		// TODO: Unsupported cloud
		appConfig.HttpPort = 8080
		appConfig.Environment = "local"
	} else {
		p, _ := strconv.Atoi(port)
		appConfig.HttpPort = int32(p)
		appConfig.Environment = cloud
	}

	if appConfig.VaultAddr == "" || appConfig.VaultEngineName == "" || appConfig.VaultStatePath == "" ||
		!(appConfig.VaultToken != "" || (appConfig.VaultAppRoleId != "" && appConfig.VaultAppRoleSecret != "")) {
		log.Fatalf("vault is not correctly configured, please refer to the documentation for more instructions")
	}

	if appConfig.AcmeEmail == "" {
		log.Fatalf("ACME configuration is not valid, please refer to the documentation for more instructions")
	}

	// Telemetry
	if appConfig.JaegerEndpoint != "" && appConfig.UseTelemetry == "" {
		appConfig.UseTelemetry = "remote"
	}

	switch appConfig.UseTelemetry {
	case "remote":
		log.Infof("jaeger Telemetry enabled")
		// init tracer jaeger
		// TODO: #166 Send unique identifier as serviceInstanceIDKey
		tp, err = utils.InitTracerJaeger(appConfig.JaegerEndpoint, configuration.OTName, configuration.OTName, appConfig.Environment)
		if err != nil {
			log.Fatal(err)
		}
	case "local":
		log.Infof("stdout Telemetry enabled")
		// init tracer jaeger
		tp, err = utils.InitTracerStdout()
		if err != nil {
			log.Fatal(err)
		}
	}

	// Trigger context cancellation token on SIGINT/SIGTERM
	go func() {
		<-cSignal
		log.Warnf("SIGTERM received, attempting graceful exit.")
		cancel()
	}()

	// Start the API HTTP Server
	log.Info("starting webapi handler")
	concurrency.GlobalWaitGroup.Add(1)
	go api.StartGin(ctx)

	// Block until cancellation signal is received
	<-ctx.Done()

	// Clean up and attempt graceful exit
	log.Infof("graceful shutdown initiated. waiting for %d seconds before forced exit", appConfig.CleanupTimeoutSec)
	ctx, cancel = context.WithTimeout(context.Background(), time.Second*time.Duration(appConfig.CleanupTimeoutSec))
	go func() {
		// Eventual clean-up logic would go in this block
		if tp != nil {
			concurrency.GlobalWaitGroup.Add(1)
			go func() {
				defer concurrency.GlobalWaitGroup.Done()
				log.Debugf("shutting down telemetry provider")
				if err = tp.Shutdown(context.Background()); err != nil {
					log.Errorf("error shutting down tracer provider: %v", err)
				}
				log.Debugf("telemetry provider terminated")
			}()
		}
		concurrency.GlobalWaitGroup.Wait()
		log.Infof("cleanup done")
		cancel()
	}()
	<-ctx.Done()
	log.Info("exiting")
}
