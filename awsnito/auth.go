package awsnito

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/d-pollard/go-shove/models"
	"github.com/dgrijalva/jwt-go"
	"os"
	"strconv"
	"time"
)

var ses = session.Must(session.NewSession())
var cogClient = cognitoidentityprovider.New(ses)
var clientId = os.Getenv("CLIENT_ID")
var attr = []string{"email", "name", "updated_at"}
var authFlow = "USER_PASSWORD_AUTH"
var jwkUrl = fmt.Sprintf(jwkUri, os.Getenv("AWS_REGION"), os.Getenv("POOL_ID"))
var jwkMap = getJWK(jwkUrl + "/.well-known/jwks.json")

func SignUp(user string, pass string, email string, name string) (*cognitoidentityprovider.SignUpOutput, error) {
	updatedAt := strconv.FormatInt(time.Now().Unix(), 10)
	shash := secretHash(user, clientId, os.Getenv("CLIENT_SECRET"))
	return cogClient.SignUp(&cognitoidentityprovider.SignUpInput{
		ClientId:   &clientId,
		Username:   &user,
		Password:   &pass,
		SecretHash: &shash,
		UserAttributes: []*cognitoidentityprovider.AttributeType{
			&cognitoidentityprovider.AttributeType{
				Name:  &attr[0],
				Value: &email,
			},
			&cognitoidentityprovider.AttributeType{
				Name:  &attr[1],
				Value: &name,
			},
			&cognitoidentityprovider.AttributeType{
				Name:  &attr[2],
				Value: &updatedAt,
			},
		},
	})
}

func ConfirmSignUp(code, user string) (*cognitoidentityprovider.ConfirmSignUpOutput, error) {
	shash := secretHash(user, clientId, os.Getenv("CLIENT_SECRET"))
	return cogClient.ConfirmSignUp(&cognitoidentityprovider.ConfirmSignUpInput{
		ClientId:         &clientId,
		ConfirmationCode: &code,
		SecretHash:       &shash,
		Username:         &user,
	})
}

func LogIn(user, pass string) (*cognitoidentityprovider.InitiateAuthOutput, error) {
	shash := secretHash(user, clientId, os.Getenv("CLIENT_SECRET"))
	return cogClient.InitiateAuth(&cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: &authFlow,
		AuthParameters: map[string]*string{
			"USERNAME":    &user,
			"PASSWORD":    &pass,
			"SECRET_HASH": &shash,
		},
		ClientId: &clientId,
	})
}

func ValidateJwt(jwtStr string) (*models.AuthenticatedUser, error) {
	token, err := pullToken(jwtStr)
	authedUser := models.AuthenticatedUser{}

	if err != nil {
		return &authedUser, err
	}

	if !token.Valid {
		return &authedUser, fmt.Errorf("token is not valid [2]")
	}

	authedUser.IsTokenValid = token.Valid
	muhClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return &authedUser, fmt.Errorf("claims unable to varify")
	}
	claimsToUser(muhClaims, &authedUser)

	return &authedUser, nil
}

func ForgotPassword(user string) (*cognitoidentityprovider.ForgotPasswordOutput, error) {
	return cogClient.ForgotPassword(&cognitoidentityprovider.ForgotPasswordInput{
		ClientId:   &clientId,
		SecretHash: aws.String(secretHash(user, clientId, os.Getenv("CLIENT_SECRET"))),
		Username:   &user,
	})
}

func ConfirmForgotPassword(code, user, pass string) (*cognitoidentityprovider.ConfirmForgotPasswordOutput, error) {
	return cogClient.ConfirmForgotPassword(&cognitoidentityprovider.ConfirmForgotPasswordInput{
		ClientId:         &clientId,
		ConfirmationCode: &code,
		Password:         &pass,
		SecretHash:       aws.String(secretHash(user, clientId, os.Getenv("CLIENT_SECRET"))),
		Username:         &user,
	})
}

func ChangePassword(accessToken, pass, newPass string) (*cognitoidentityprovider.ChangePasswordOutput, error) {
	return cogClient.ChangePassword(&cognitoidentityprovider.ChangePasswordInput{
		AccessToken:      aws.String(accessToken),
		PreviousPassword: aws.String(pass),
		ProposedPassword: aws.String(newPass),
	})
}

func ResendSignUpCode(user string) (*cognitoidentityprovider.ResendConfirmationCodeOutput, error) {
	return cogClient.ResendConfirmationCode(&cognitoidentityprovider.ResendConfirmationCodeInput{
		ClientId:   aws.String(clientId),
		SecretHash: aws.String(secretHash(user, clientId, os.Getenv("CLIENT_SECRET"))),
		Username:   aws.String(user),
	})
}
