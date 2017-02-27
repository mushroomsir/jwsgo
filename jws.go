package jwsgo

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

var hasher = Hash

//New return a jws instance
func New(key string) *JWS {
	return &JWS{key: key}
}

// JWS ...
type JWS struct {
	key string
}

// SetHash set a global hash function for signing, default to:
//
// func Hash(key, data string) (sig []byte) {
// 	mac := hmac.New(sha256.New, []byte(key))
// 	mac.Write([]byte(data))
// 	return mac.Sum(nil)
// }
//
func (jws *JWS) SetHash(fn func(key, data string) []byte) {
	if fn == nil {
		panic("invalid hash function")
	}
	hasher = fn
}

//Hash the default hash function
func Hash(key, data string) (sig []byte) {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// Encode the jws header and payload return token
func (jws *JWS) Encode(header *Header, payload *Payload) (token string, err error) {
	head, err := header.Encode()
	cs, err := payload.Encode()

	ss := fmt.Sprintf("%s.%s", head, cs)

	sig := hasher(jws.key, ss)
	token = fmt.Sprintf("%s.%s", ss, base64.RawURLEncoding.EncodeToString(sig))
	return
}

//Payload  contains information about the JWT signature including the permissions being requested (scopes),
// the target of the token, the issuer, the time the token was issued, and the lifetime of the token.
type Payload struct {
	Iss   string `json:"iss"`             // email address of the client_id of the application making the access token request
	Scope string `json:"scope,omitempty"` // space-delimited list of the permissions the application requests
	Aud   string `json:"aud,omitempty"`   // descriptor of the intended target of the assertion (Optional).
	EXP   int64  `json:"exp"`             // the expiration time of the assertion (seconds since Unix epoch)
	Iat   int64  `json:"iat"`             // the time the assertion was issued (seconds since Unix epoch)
	Typ   string `json:"typ,omitempty"`   // token type (Optional).
	// Email for which the application is requesting delegated access (Optional).
	Sub            string                 `json:"sub,omitempty"`
	PrivatePayload map[string]interface{} `json:"-"`
}

//Encode the current payload of jwt
func (c *Payload) Encode() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	if len(c.PrivatePayload) == 0 {
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	// Marshal private payload set and then append it to b.
	prv, err := json.Marshal(c.PrivatePayload)
	if err != nil {
		return "", fmt.Errorf("jws: invalid map of private claims %v", c.PrivatePayload)
	}

	// Concatenate public and private claim JSON objects.
	if !bytes.HasSuffix(b, []byte{'}'}) {
		return "", fmt.Errorf("jws: invalid JSON %s", b)
	}
	if !bytes.HasPrefix(prv, []byte{'{'}) {
		return "", fmt.Errorf("jws: invalid JSON %s", prv)
	}
	b[len(b)-1] = ','         // Replace closing curly brace with a comma.
	b = append(b, prv[1:]...) // Append private claims.
	return base64.RawURLEncoding.EncodeToString(b), nil
}

//Header is header of jwt
type Header struct {
	Algorithm string `json:"alg"`
	// Represents the token type.
	Typ string `json:"typ"`
	// The optional hint of which key is being used.
	KeyID         string                 `json:"kid,omitempty"`
	PrivateHeader map[string]interface{} `json:"-"`
}

//Encode the current header of jwt
func (h *Header) Encode() (string, error) {
	if h.Typ == "" {
		h.Typ = "JWT"
	}
	b, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	if len(h.PrivateHeader) == 0 {
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	// Marshal private header and then append it to b.
	prv, err := json.Marshal(h.PrivateHeader)
	if err != nil {
		return "", fmt.Errorf("jws: invalid map of private claims %v", h.PrivateHeader)
	}

	// Concatenate public and private claim JSON objects.
	if !bytes.HasSuffix(b, []byte{'}'}) {
		return "", fmt.Errorf("jws: invalid JSON %s", b)
	}
	if !bytes.HasPrefix(prv, []byte{'{'}) {
		return "", fmt.Errorf("jws: invalid JSON %s", prv)
	}
	b[len(b)-1] = ','         // Replace closing curly brace with a comma.
	b = append(b, prv[1:]...) // Append private claims.
	return base64.RawURLEncoding.EncodeToString(b), nil
}
