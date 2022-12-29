package logic

import (
	"certificate-issuer/api/v1/model"
	"certificate-issuer/configuration"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/coderollers/go-logger"
	"github.com/coderollers/go-utils"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/hashicorp/vault/api"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"software.sslmate.com/src/go-pkcs12"
)

func VaultStoreCertificate(ctx context.Context, tracer oteltrace.Tracer, appConfig *configuration.Configuration,
	vault *api.Client, configs []model.CertificateConfiguration, toDelete []string, normalizedDomain string, certificates *certificate.Resource) ([]error, bool) {
	var (
		err        error
		errList    []error
		span       oteltrace.Span
		secretData = map[string]interface{}{}
		pfxBytes   []byte
	)

	ctx, span = tracer.Start(ctx, "Store certificate configuration in vault")
	defer span.End()

	secretData = map[string]interface{}{"Status": "Removed"}
	for _, path := range toDelete {
		if _, err = vault.KVv2(appConfig.VaultEngineName).Put(ctx, path, secretData); err != nil {
			span.RecordError(err)
			errList = append(errList, fmt.Errorf("error disabling certificate secret %s: %w", path, err))
		}
	}

	span.AddEvent("Add certificate to configuration sub-path")
	// We store the certificate within the Config secret as well for easy retrieval
	secretData = map[string]interface{}{
		"private": string(certificates.PrivateKey),
		"public":  string(certificates.Certificate),
	}
	if _, err = vault.KVv2(appConfig.VaultEngineName).Put(ctx, fmt.Sprintf("%s/%s/%s", appConfig.VaultStatePath, configuration.VaultStateCertificatesSubPath, normalizedDomain), secretData); err != nil {
		span.RecordError(err)
		errList = append(errList, fmt.Errorf("error storing certificate in config subpath: %w", err))
		// We must return here, if this fails then renewal will be impossible
		return errList, true
	}

	for _, config := range configs {
		span.AddEvent("Add certificate to path", oteltrace.WithAttributes(attribute.String("path", config.Path)))
		secretData = map[string]interface{}{}
		// TODO: #171 Support encrypted PEM certificates
		if config.PemPrivateCertificateKey != "" && config.PemPublicCertificateKey != "" {
			secretData[config.PemPrivateCertificateKey] = string(certificates.PrivateKey)
			secretData[config.PemPublicCertificateKey] = string(certificates.Certificate)
		}

		if config.PfxCertificateKey != "" && config.PasswordKey != "" {
			certDer, _ := pem.Decode(certificates.IssuerCertificate)
			caCert, _ := x509.ParseCertificates(certDer.Bytes)
			certDer, _ = pem.Decode(certificates.PrivateKey)
			keyRsa, _ := x509.ParsePKCS1PrivateKey(certDer.Bytes)
			certDer, _ = pem.Decode(certificates.Certificate)
			certs, _ := x509.ParseCertificates(certDer.Bytes)
			password := utils.RandomString(16)
			if pfxBytes, err = pkcs12.Encode(rand.Reader, keyRsa, certs[0], caCert, password); err != nil {
				span.RecordError(err)
				errList = append(errList, fmt.Errorf("error during PKCS12 certificate generation: %w", err))
			} else {
				secretData[config.PfxCertificateKey] = base64.StdEncoding.EncodeToString(pfxBytes)
				secretData[config.PasswordKey] = password
				if config.ThumbprintKey != "" {
					secretData[config.ThumbprintKey] = fmt.Sprintf("%X", sha1.Sum(certDer.Bytes))
				}
			}
		}
		if _, err = vault.KVv2(appConfig.VaultEngineName).Put(ctx, config.Path, secretData); err != nil {
			span.RecordError(err)
			errList = append(errList, fmt.Errorf("error storing certificate secret %s: %w", config.Path, err))
		}
	}
	return errList, false
}

func VaultStoreCertificateConfigurations(ctx context.Context, tracer oteltrace.Tracer, appConfig *configuration.Configuration, vault *api.Client,
	domain string, cc []model.CertificateConfiguration) (*api.KVSecret, error) {
	var (
		err        error
		span       oteltrace.Span
		secret     *api.KVSecret
		secretData = map[string]interface{}{}
	)

	ctx, span = tracer.Start(ctx, "Store certificate configuration in vault")
	defer span.End()

	for _, c := range cc {
		secretData[c.Path] = c.Serialize()
	}

	if secret, err = vault.KVv2(appConfig.VaultEngineName).Put(
		ctx, fmt.Sprintf("%s/%s/%s", appConfig.VaultStatePath, configuration.VaultStateCertificateConfigurationsSubPath, domain), secretData); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("error storing acme user secret: %w", err)
	}

	return secret, nil
}

func VaultGetCertificateConfigurations(ctx context.Context, tracer oteltrace.Tracer, appConfig *configuration.Configuration,
	vault *api.Client, domain string) (map[string]model.CertificateConfiguration, error) {
	var (
		err                 error
		span                oteltrace.Span
		secret              *api.KVSecret
		vaultConfigurations = map[string]model.CertificateConfiguration{}
	)

	ctx, span = tracer.Start(ctx, "Get certificate configurations from vault")
	defer span.End()

	span.AddEvent("Retrieve secret from vault")
	if secret, err = vault.KVv2(appConfig.VaultEngineName).Get(
		ctx, fmt.Sprintf("%s/%s/%s", appConfig.VaultStatePath, configuration.VaultStateCertificateConfigurationsSubPath, domain)); err != nil && !errors.Is(err, api.ErrSecretNotFound) {
		span.RecordError(err)
		return nil, fmt.Errorf("error retrieving acme state secret: %w", err)
	}
	if secret != nil {
		span.AddEvent("Process vault configurations")
		for _, config := range secret.Data {
			var (
				c  model.CertificateConfiguration
				cc map[string]interface{}
				ok bool
			)
			if cc, ok = config.(map[string]interface{}); !ok {
				return nil, fmt.Errorf("error while parsing certificate configuration: null value encountered")
			}
			if err = c.Deserialize(cc); err != nil {
				span.RecordError(err)
				return nil, fmt.Errorf("error while parsing certificate configuration: %w", err)
			}
			vaultConfigurations[c.Path] = c
		}
	}
	return vaultConfigurations, nil
}

func VaultReconcileCertificateConfigurations(ctx context.Context, tracer oteltrace.Tracer, cc []model.CertificateConfiguration,
	vaultConfigs map[string]model.CertificateConfiguration) ([]model.CertificateConfiguration, []string) {
	var (
		span     oteltrace.Span
		vc       []model.CertificateConfiguration
		toDelete []string
		log      = logger.SugaredLogger().WithContextCorrelationId(ctx).With("package", "logic", "action", "VaultReconcileCertificateConfigurations")
	)

	ctx, span = tracer.Start(ctx, "Reconcile certificate configurations")
	defer span.End()

	for _, config := range cc {
		vc = append(vc, config)
		delete(vaultConfigs, config.Path)
	}
	log.Debugf("new configurations: %v", vc)

	for _, config := range vaultConfigs {
		toDelete = append(toDelete, config.Path)
	}
	log.Debugf("to disable %d configurations", len(toDelete))

	return vc, toDelete
}

func VaultGetCertificate(ctx context.Context, tracer oteltrace.Tracer, appConfig *configuration.Configuration, vault *api.Client, domain string) ([]byte, []byte, error) {
	var (
		err     error
		span    oteltrace.Span
		secret  *api.KVSecret
		private string
		public  string
	)

	ctx, span = tracer.Start(ctx, "Get certificate from vault")
	defer span.End()

	span.AddEvent("Retrieve secret from vault")
	if secret, err = vault.KVv2(appConfig.VaultEngineName).Get(
		ctx, fmt.Sprintf("%s/%s/%s", appConfig.VaultStatePath, configuration.VaultStateCertificatesSubPath, domain)); err != nil && !errors.Is(err, api.ErrSecretNotFound) {
		span.RecordError(err)
		return nil, nil, fmt.Errorf("error retrieving acme state secret: %w", err)
	}
	if secret != nil {
		private, _ = secret.Data["private"].(string)
		public, _ = secret.Data["public"].(string)
	} else {
		return nil, nil, errors.New("secret data was nil, this should not happen")
	}

	return []byte(private), []byte(public), nil
}

func VaultGetCertificateList(ctx context.Context, tracer oteltrace.Tracer, appConfig *configuration.Configuration, vault *api.Client) ([]string, error) {
	var (
		err     error
		span    oteltrace.Span
		secret  *api.Secret
		domains []string
	)

	ctx, span = tracer.Start(ctx, "Get certificate list from vault")
	defer span.End()

	span.AddEvent("Retrieve secret list from vault")
	if secret, err = vault.Logical().ListWithContext(ctx, fmt.Sprintf("%s/metadata/%s/%s", appConfig.VaultEngineName,
		appConfig.VaultStatePath, configuration.VaultStateCertificatesSubPath)); err != nil || secret == nil {
		span.RecordError(err)
		return nil, fmt.Errorf("error list secrets: %w", err)
	}

	if secret.Data != nil {
		for _, data := range secret.Data["keys"].([]interface{}) {
			domains = append(domains, data.(string))
		}
	}

	return domains, nil

}
