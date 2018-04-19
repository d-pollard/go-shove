package awsnito

import (
	"net/http"
	"encoding/json"
	"time"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"encoding/binary"
	"github.com/dgrijalva/jwt-go"
	"fmt"
	"strings"
	"github.com/d-pollard/go-shove/models"
	"crypto/hmac"
	"crypto/sha256"
)

type JWKKey struct {
	Alg string
	E   string
	Kid string
	Kty string
	N   string
	Use string
}
type JWK struct {
	Keys []JWKKey
}

var jwkUri = "https://cognito-idp.%v.amazonaws.com/%v"

func getJWK(jwkURL string) map[string]JWKKey {
	jwk := &JWK{}
	getJSON(jwkURL, jwk)

	jwkMap := make(map[string]JWKKey, 0)
	for _, entryValue := range jwk.Keys {
		jwkMap[entryValue.Kid] = entryValue
	}
	return jwkMap
}

func getJSON(url string, target interface{}) error {
	httpClient := &http.Client{
		Timeout:       10 * time.Second,
	}
	res, err := httpClient.Get(url)

	if err != nil {
		return err
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(target)
}

func convertKey(rawE, rawN string) *rsa.PublicKey {
	decodedE, err := base64.RawURLEncoding.DecodeString(rawE)
	if err != nil {
		panic(err)
	}
	if len(decodedE) < 4 {
		ndata := make([]byte, 4)
		copy(ndata[4-len(decodedE):], decodedE)
		decodedE = ndata
	}
	pubKey := &rsa.PublicKey{
		N: &big.Int{},
		E: int(binary.BigEndian.Uint32(decodedE[:])),
	}
	decodedN, err := base64.RawURLEncoding.DecodeString(rawN)
	if err != nil {
		panic(err)
	}
	pubKey.N.SetBytes(decodedN)
	return pubKey
}

func validateClaimItem(key string, keyShouldBe []string, claims jwt.MapClaims) error {
	if val, ok := claims[key]; ok {
		if valStr, ok := val.(string); ok {
			for _, shouldbe := range keyShouldBe {
				if valStr == shouldbe {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("%v does not match any of valid values: %v", key, keyShouldBe)
}

func validateAWSJwtClaims(claims jwt.MapClaims) error {
	var err error

	err = validateClaimItem("iss", []string{jwkUrl}, claims)
	if err != nil {
		return err
	}

	validateTokenUse := func() error {
		if tokenUse, ok := claims["token_use"]; ok {
			if tokenUseStr, ok := tokenUse.(string); ok {
				if tokenUseStr == "id" || tokenUseStr == "access" {
					return nil
				}
			}
		}
		return fmt.Errorf("token is wrong, access is wrong")
	}

	err = validateTokenUse()
	if err != nil {
		return err
	}
	err = validateExpired(claims)
	if err != nil {
		return err
	}

	return nil
}

func validateExpired(claims jwt.MapClaims) error {
	if tokenExp, ok := claims["exp"]; ok {
		if exp, ok := tokenExp.(float64); ok {
			now := time.Now().Unix()
			if int64(exp) > now {
				return nil
			}
		}
		return fmt.Errorf("could not parse token")
	}
	return fmt.Errorf("token has expired")
}

func pullToken(jwtStr string) (*jwt.Token, error) {

	token, err := jwt.Parse(jwtStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"]

		if !ok {
			return nil, fmt.Errorf("kid could not be found")
		}

		kidStr, ok := kid.(string)

		if !ok {
			return nil, fmt.Errorf("kid could not be converted")
		}

		key := jwkMap[kidStr]

		rsaConvKey := convertKey(key.E, key.N)
		return rsaConvKey, nil
	})

	if err != nil {
		return token, err
	}

	muhClaims := token.Claims.(jwt.MapClaims)

	issuer, ok := muhClaims["iss"]

	if !ok {
		return token, fmt.Errorf("token claim contains no issuer")
	}

	issx := issuer.(string)

	if !strings.Contains(issx, "cognito-idp") {
		return token, fmt.Errorf("token is not valid [1]")
	}

	err = validateAWSJwtClaims(muhClaims)

	if err != nil {
		return token, err
	}

	if !token.Valid {
		return token, fmt.Errorf("token invalid, sorry")
	}

	return token, nil
}

func claimsToUser(muhClaims jwt.MapClaims, authedUser *models.AuthenticatedUser) {

	if tokenUse, exists := muhClaims["token_use"]; exists {
		authedUser.TokenUse = tokenUse.(string)
	}
	if scope, exists    := muhClaims["scope"];     exists {
		authedUser.Level = scope.(string)
	}
	if authTime, exists := muhClaims["auth_time"]; exists {
		authedUser.AuthTime = authTime.(float64)
	}
	if expTime, exists  := muhClaims["exp"];       exists {
		authedUser.TokenExpireTime = expTime.(float64)
	}
	if clientID, exists := muhClaims["client_id"]; exists {
		authedUser.ClientAppID = clientID.(string)
	}
	if uuid, exists     := muhClaims["sub"];       exists {
		authedUser.UUID = uuid.(string)
	}
	if username, exists := muhClaims["username"];  exists {
		authedUser.Username = username.(string)
	}
}

func SecretHash(username, clientID, clientSecret string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
