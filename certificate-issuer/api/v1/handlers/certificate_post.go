package handlers

import (
	"certificate-issuer/api/v1/logic"
	"certificate-issuer/api/v1/model"
	"certificate-issuer/api/v1/response"
	"certificate-issuer/configuration"
	"errors"

	"github.com/coderollers/go-logger"
	"github.com/coderollers/go-stats/concurrency"
	"github.com/coderollers/go-utils"
	"github.com/gin-gonic/gin"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/hashicorp/vault/api"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func CertificatePost(c *gin.Context) {
	concurrency.GlobalWaitGroup.Add(1)
	defer concurrency.GlobalWaitGroup.Done()
	log := logger.SugaredLogger().WithContextCorrelationId(c).With("package", "handlers", "action", "CertificatePut")

	var (
		rr            model.CertificateRequest
		err           error
		span          oteltrace.Span
		acmeClient    *lego.Client
		certificates  *certificate.Resource
		certConfigs   map[string]model.CertificateConfiguration
		ctx           = c.Request.Context()
		vault         = c.MustGet(configuration.VaultContextKey).(*api.Client)
		correlationId = c.MustGet(configuration.CorrelationIdKey).(string)
		appConfig     = configuration.AppConfig()
	)

	if err = c.ShouldBindJSON(&rr); err != nil {
		log.Errorf("error while deserializing request: %s", err.Error())
		response.FailureResponse(c, nil, utils.HttpError{Code: 400, Err: err})
		return
	}

	if err = rr.Validate(); err != nil {
		log.Errorf("error while validating request: %s", err.Error())
		response.FailureResponse(c, nil, utils.HttpError{Code: 400, Err: err})
		return
	}
	log.Debugf("payload: %v", rr)

	// TODO: Add attributes
	ctx, span = tracer.Start(ctx, "Request a new certificate",
		oteltrace.WithAttributes(attribute.StringSlice("Domains", rr.GetDomainsAsSlice()),
			attribute.String("CorrelationId", correlationId)))
	defer span.End()

	if acmeClient, err = logic.NewAcmeClient(ctx, tracer, appConfig, vault); err != nil {
		log.Errorf("%s", err.Error())
		response.FailureResponse(c, nil, utils.HttpError{
			Code: 503,
			Err:  err,
		})
		return
	}

	if certConfigs, err = logic.VaultGetCertificateConfigurations(ctx, tracer, appConfig, vault, rr.GetNormalizedDomain()); err != nil {
		log.Errorf("%s", err.Error())
		response.FailureResponse(c, nil, utils.HttpError{
			Code: 503,
			Err:  err,
		})
		return
	}

	newCertConfigs, disabledCertPaths := logic.VaultReconcileCertificateConfigurations(ctx, tracer, rr.CertificateConfigurations, certConfigs)

	if _, err = logic.VaultStoreCertificateConfigurations(ctx, tracer, appConfig, vault, rr.GetNormalizedDomain(), newCertConfigs); err != nil {
		log.Errorf("%s", err.Error())
		response.FailureResponse(c, nil, utils.HttpError{
			Code: 503,
			Err:  err,
		})
		return
	}

	// TODO: #170 Support dynamic provider for DNS challenge
	if err = logic.UseCloudflareAcmeProvider(ctx, tracer, acmeClient); err != nil {
		log.Errorf("%s", err.Error())
		response.FailureResponse(c, nil, utils.HttpError{
			Code: 503,
			Err:  err,
		})
		return
	}

	if certificates, err = logic.AcmeRequestCertificate(ctx, tracer, acmeClient, rr.GetDomainsAsSlice()); err != nil {
		log.Errorf("%s", err.Error())
		response.FailureResponse(c, nil, utils.HttpError{
			Code: 503,
			Err:  err,
		})
		return
	}

	errList, fatal := logic.VaultStoreCertificate(ctx, tracer, appConfig, vault, newCertConfigs, disabledCertPaths, rr.GetNormalizedDomain(), certificates)
	if fatal {
		for _, err = range errList {
			log.Errorf("%s", err)
		}
		response.FailureResponse(c, nil, utils.HttpError{
			Code:    503,
			Err:     errors.New("unrecoverable error, try again later"),
			Message: "",
		})
		return
	}

	for _, err = range errList {
		log.Warnf("%s", err)
	}

	log.Infof("certificate issued: %s", rr.GetNormalizedDomain())
	response.SuccessResponse(c, struct{ ErrorCount int }{ErrorCount: len(errList)})
}
