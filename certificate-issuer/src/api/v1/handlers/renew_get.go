package handlers

import (
	"certificate-issuer/api/v1/logic"
	"certificate-issuer/api/v1/model"
	"certificate-issuer/api/v1/response"
	"certificate-issuer/configuration"
	"crypto/x509"
	"encoding/pem"
	"github.com/coderollers/go-logger"
	"github.com/coderollers/go-stats/concurrency"
	"github.com/coderollers/go-utils"
	"github.com/gin-gonic/gin"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/hashicorp/vault/api"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"time"
)

func RenewGet(c *gin.Context) {
	concurrency.GlobalWaitGroup.Add(1)
	defer concurrency.GlobalWaitGroup.Done()
	log := logger.SugaredLogger().WithContextCorrelationId(c).With("package", "handlers", "action", "RenewGet")

	var (
		cnt, cntFailed  int
		cntRenewed      int
		err             error
		errList         []error
		span            oteltrace.Span
		certificateList []string
		acmeClient      *lego.Client
		certificates    *certificate.Resource
		certConfigsMap  map[string]model.CertificateConfiguration
		certConfigs     []model.CertificateConfiguration
		ctx             = c.Request.Context()
		vault           = c.MustGet(configuration.VaultContextKey).(*api.Client)
		correlationId   = c.MustGet(configuration.CorrelationIdKey).(string)
		appConfig       = configuration.AppConfig()
		normalizedName  = c.Param("name")
	)

	// TODO: Add attributes
	ctx, span = tracer.Start(ctx, "Request a new certificate",
		oteltrace.WithAttributes(attribute.String("NormalizedName", normalizedName),
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

	if normalizedName != "" {
		certificateList = []string{normalizedName}
	} else {
		if certificateList, err = logic.VaultGetCertificateList(ctx, tracer, appConfig, vault); err != nil {
			log.Errorf("%s", err.Error())
			response.FailureResponse(c, nil, utils.HttpError{
				Code: 503,
				Err:  err,
			})
			return
		}
	}

	for _, normalizedName = range certificateList {
		cnt++
		if certConfigsMap, err = logic.VaultGetCertificateConfigurations(ctx, tracer, appConfig, vault, normalizedName); err != nil {
			log.Errorf("%s", err.Error())
			response.FailureResponse(c, nil, utils.HttpError{
				Code: 503,
				Err:  err,
			})
			return
		}

		certConfigs = []model.CertificateConfiguration{}
		for _, config := range certConfigsMap {
			certConfigs = append(certConfigs, config)
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

		private, public, err := logic.VaultGetCertificate(ctx, tracer, appConfig, vault, normalizedName)
		if err != nil || private == nil || public == nil {
			log.Errorf("error retrieving certificate from vault: %s", err)
			errList = append(errList, err)
			cntFailed++
			continue
		}

		certToRenew := certificate.Resource{
			PrivateKey:  private,
			Certificate: public,
		}

		publicDer, _ := pem.Decode(public)
		publicCert, err := x509.ParseCertificate(publicDer.Bytes)
		if err != nil {
			log.Errorf("error parsing certificate: %s", err.Error())
			errList = append(errList, err)
			cntFailed++
			continue
		}
		if publicCert.NotAfter.Sub(time.Now().UTC()).Hours() <= float64(appConfig.HoursForRenewal) {
			log.Infof("certificate %s expiring in less than 15 days, renewing", normalizedName)
			if certificates, err = logic.AcmeRenewCertificate(ctx, tracer, acmeClient, certToRenew); err != nil {
				log.Errorf("%s", err.Error())
				errList = append(errList, err)
				cntFailed++
				continue
			}

			el, _ := logic.VaultStoreCertificate(ctx, tracer, appConfig, vault, certConfigs, []string{}, normalizedName, certificates)
			for _, e := range el {
				errList = append(errList, e)
			}
			cntRenewed++
		} else {
			log.Infof("certificate %s expiring in more than 15 days, not renewing", normalizedName)
		}
	}

	for _, err = range errList {
		log.Warnf("%s", err)
	}

	log.Infof("total: %d, renewed: %d, failed: %d, errors: %d", cnt, cntRenewed, cntFailed, len(errList))
	response.SuccessResponse(c,
		struct{ Total, Renewed, FailedToRenew, ErrorCount int }{
			Total:         cnt,
			Renewed:       cntRenewed,
			FailedToRenew: cntFailed,
			ErrorCount:    len(errList),
		})
}
