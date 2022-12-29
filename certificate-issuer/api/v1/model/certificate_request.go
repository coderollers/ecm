package model

import (
	"errors"
	"fmt"
	"strings"
)

type CertificateConfiguration struct {
	Path                     string `json:"Path" example:"/dev/mtls"`
	PemPrivateCertificateKey string `json:"PemPrivateCertificateKey,omitempty" example:"tls.key"`
	PemPublicCertificateKey  string `json:"PemPublicCertificateKey,omitempty" example:"tls.crt"`
	PfxCertificateKey        string `json:"PfxCertificateKey,omitempty" example:"tls.pfx"`
	PasswordKey              string `json:"PasswordKey,omitempty" example:"password"`
	ThumbprintKey            string `json:"ThumbprintKey,omitempty" example:"thumbprint"`
}

func (c *CertificateConfiguration) Serialize() map[string]interface{} {
	data := map[string]interface{}{"Path": c.Path}
	if c.PemPrivateCertificateKey != "" {
		data["PemPrivateCertificateKey"] = c.PemPrivateCertificateKey

	}
	if c.PemPublicCertificateKey != "" {
		data["PemPublicCertificateKey"] = c.PemPublicCertificateKey

	}
	if c.PfxCertificateKey != "" {
		data["PfxCertificateKey"] = c.PfxCertificateKey

	}
	if c.PasswordKey != "" {
		data["PasswordKey"] = c.PasswordKey

	}
	if c.ThumbprintKey != "" {
		data["ThumbprintKey"] = c.ThumbprintKey

	}

	return data
}

func (c *CertificateConfiguration) Deserialize(data map[string]interface{}) error {
	var ok bool
	if data == nil {
		return errors.New("secret data is nil")
	}

	if c.Path, ok = data["Path"].(string); !ok {
		return fmt.Errorf("path value type assertion failed: %T %#v", data["Email"], data["Email"])
	}
	c.PemPrivateCertificateKey, ok = data["PemPrivateCertificateKey"].(string)
	c.PemPublicCertificateKey, ok = data["PemPublicCertificateKey"].(string)
	c.PfxCertificateKey, ok = data["PfxCertificateKey"].(string)
	c.PasswordKey, ok = data["PasswordKey"].(string)
	c.ThumbprintKey, ok = data["ThumbprintKey"].(string)

	return nil
}

type CertificateRequest struct {
	Request `json:"-" swaggerignore:"true"`

	Domains                   string                     `json:"Domains" example:"*.example.com, *.example.net"`
	CertificateConfigurations []CertificateConfiguration `json:"CertificateConfigurations"`
}

func (cr *CertificateRequest) Validate() error {
	if strings.TrimSpace(cr.Domains) == "" {
		return errors.New("missing required parameter: Domains")
	}

	if cr.CertificateConfigurations == nil || len(cr.CertificateConfigurations) == 0 {
		return errors.New("missing required parameter: CertificateConfigurations")
	}

	for i, config := range cr.CertificateConfigurations {
		if config.Path == "" {
			return fmt.Errorf("missing required parameter: CertificateConfiguration[%d].Path", i)
		}
		if !(config.PemPublicCertificateKey != "" && config.PemPrivateCertificateKey != "") && !(config.PfxCertificateKey != "" && config.PasswordKey != "") {
			return errors.New("you must specify at least one of PEM or PFX configuration key")
		}
	}
	return nil
}

func (cr *CertificateRequest) GetDomainsAsSlice() []string {
	tokenized := strings.Split(cr.Domains, ",")
	var domains []string
	for _, token := range tokenized {
		domains = append(domains, strings.TrimSpace(token))
	}
	return domains
}

func (cr *CertificateRequest) GetNormalizedDomain() string {
	domains := cr.GetDomainsAsSlice()
	if len(domains) == 0 {
		return ""
	}
	return strings.TrimLeft(domains[0], "*.")
}
