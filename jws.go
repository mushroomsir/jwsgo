package jwsgo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

//New ...
func New(key string) *JWS {
	return &JWS{key: key}
}

//JWS ...
type JWS struct {
	key string
}

//GetSign ...
func (jws *JWS) GetSign(data []byte) (sig []byte, err error) {
	mac := hmac.New(sha256.New, []byte(jws.key))
	_, err = mac.Write(data)
	if err == nil {
		sig = mac.Sum(nil)
		return
	}
	return
}

// Encode ...
func (jws *JWS) Encode(header *Header, payload *Payload) (token string, err error) {
	head, err := header.Encode()
	cs, err := payload.Encode()

	ss := fmt.Sprintf("%s.%s", head, cs)

	sig, err := jws.GetSign([]byte(ss))
	token = fmt.Sprintf("%s.%s", ss, base64.RawURLEncoding.EncodeToString(sig))
	return
}

//Payload ...
type Payload struct {
	ID  string `json:"id"`
	EXP int64  `json:"exp"`
	Typ string `json:"typ"`
    Scope string `json:"scope,omitempty"` // space-delimited list of the permissions the application requests
}

//Encode ...
func (c *Payload) Encode() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

//Header ...
type Header struct {
	Algorithm string `json:"alg"`
     // Represents the token type.
    Typ string `json:"typ,omitempty"`
    // The optional hint of which key is being used.
    KeyID string `json:"kid,omitempty"`
}

//Encode ...
func (h *Header) Encode() (string, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
