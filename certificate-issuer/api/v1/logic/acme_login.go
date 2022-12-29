package logic

import (
	"certificate-issuer/api/v1/model"
	"certificate-issuer/configuration"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/vault/api"
	oteltrace "go.opentelemetry.io/otel/trace"
)

type AcmeUserSecret struct {
	Email string
	Key   string
}

func (u *AcmeUserSecret) Serialize() map[string]interface{} {
	return map[string]interface{}{"Email": u.Email, "Key": u.Key}
}

func (u *AcmeUserSecret) Deserialize(data map[string]interface{}) error {
	var ok bool
	if data == nil {
		return errors.New("secret data is nil")
	}

	if u.Email, ok = data["Email"].(string); !ok {
		return fmt.Errorf("email value type assertion failed: %T %#v", data["Email"], data["Email"])
	}

	if u.Key, ok = data["Key"].(string); !ok {
		return fmt.Errorf("key value type assertion failed: %T %#v", data["Key"], data["Key"])
	}
	return nil
}

func SetUpAcmeUser(ctx context.Context, tracer oteltrace.Tracer, appConfig *configuration.Configuration, vault *api.Client) (*model.AcmeUser, error) {
	var (
		err    error
		user   *model.AcmeUser
		secret *api.KVSecret
		span   oteltrace.Span
	)

	ctx, span = tracer.Start(ctx, "Set up ACME user")
	defer span.End()

	span.AddEvent("Retrieve secret from vault")
	if secret, err = vault.KVv2(appConfig.VaultEngineName).Get(ctx,
		fmt.Sprintf("%s/%s", appConfig.VaultStatePath, configuration.VaultStateAcmeUserSubPath)); err != nil && !errors.Is(err, api.ErrSecretNotFound) {
		span.RecordError(err)
		return nil, fmt.Errorf("error retrieving acme state secret: %w", err)
	}
	if secret == nil {
		span.AddEvent("Generate RSA key")
		privateKey, _ := rsa.GenerateKey(rand.Reader, 4096)
		user = &model.AcmeUser{Email: appConfig.AcmeEmail, Key: privateKey}
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		pemBytes := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: privateKeyBytes,
			})
		secretData := AcmeUserSecret{Email: appConfig.AcmeEmail, Key: string(pemBytes)}
		span.AddEvent("Store secret in vault")
		if secret, err = vault.KVv2(appConfig.VaultEngineName).Put(
			ctx, fmt.Sprintf("%s/%s", appConfig.VaultStatePath, configuration.VaultStateAcmeUserSubPath), secretData.Serialize()); err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("error storing acme user secret: %w", err)
		}
	} else {
		var aus AcmeUserSecret
		span.AddEvent("Deserialize secret data")
		if err = aus.Deserialize(secret.Data); err != nil {
			span.RecordError(err)
			return nil, err
		}
		if aus.Email != appConfig.AcmeEmail {
			// Email has changed
			// TODO: #169 Support for changing the email of the ACME user
			return /*user*/ nil, fmt.Errorf("email change not supported yet, please use the email %s", aus.Email)
		}
		span.AddEvent("Parse private key data")
		privateKeyBytes, _ := pem.Decode([]byte(aus.Key))
		privateKey, e := x509.ParsePKCS1PrivateKey(privateKeyBytes.Bytes)
		if e != nil {
			return nil, fmt.Errorf("error parsing private key: %w", e)
		}
		user = &model.AcmeUser{Email: appConfig.AcmeEmail, Key: privateKey}
	}
	return user, nil
}

func NewAcmeClient(ctx context.Context, tracer oteltrace.Tracer, appConfig *configuration.Configuration, vault *api.Client) (*lego.Client, error) {
	var (
		err        error
		acmeUser   *model.AcmeUser
		acmeClient *lego.Client
		span       oteltrace.Span
	)
	ctx, span = tracer.Start(ctx, "Creating ACME client")
	defer span.End()

	if acmeUser, err = SetUpAcmeUser(ctx, tracer, appConfig, vault); err != nil {
		if acmeUser != nil {
			// Email changed
			// TODO: #169 Support for changing the email of the ACME user
		}
		span.RecordError(err)
		return nil, err
	}
	span.AddEvent("Instantiate client")
	config := lego.NewConfig(acmeUser)
	if appConfig.StagingAcme {
		config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	if acmeClient, err = lego.NewClient(config); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("error creating new ACME client: %w", err)
	}
	span.AddEvent("Register user with ACME directory")
	if acmeUser.Registration, err = acmeClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true}); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("ACME registration failed: %w", err)
	}

	return acmeClient, nil
}
