package logic

import (
	"context"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func AcmeRequestCertificate(ctx context.Context, tracer oteltrace.Tracer, client *lego.Client, domains []string) (*certificate.Resource, error) {
	var (
		err  error
		span oteltrace.Span
		cert *certificate.Resource
	)

	ctx, span = tracer.Start(ctx, "Request certificate via ACME")
	defer span.End()

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	if cert, err = client.Certificate.Obtain(request); err != nil {
		span.RecordError(err)
		return nil, err
	}

	return cert, nil
}
