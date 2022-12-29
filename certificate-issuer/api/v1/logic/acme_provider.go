package logic

import (
	"context"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func UseCloudflareAcmeProvider(ctx context.Context, tracer oteltrace.Tracer, client *lego.Client) error {
	_, span := tracer.Start(ctx, "Activate Cloudflare DNS01 provider")
	defer span.End()

	provider, err := cloudflare.NewDNSProvider()
	if err != nil {
		return err
	}

	return client.Challenge.SetDNS01Provider(provider)
}
