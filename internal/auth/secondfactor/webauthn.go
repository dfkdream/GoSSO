package secondfactor

import "github.com/duo-labs/webauthn/webauthn"

type WebAuthn struct {
	Credentials []*webauthn.Credential
}

func (wa WebAuthn) DisplayName() string {
	return "FIDO U2F"
}

func (wa WebAuthn) Icon() string {
	return "usb-token"
}

func (wa WebAuthn) Endpoint() string {
	return "/2fa/webauthn"
}
