# GO Cognito Auth Helper

## Required env variables
```dotenv
AWS_SECRET_ACCESS_KEY={AWS_COGNITO_ACCESS_KEY}
AWS_ACCESS_KEY_ID={AWS_COGNITO_ACCESS_KEY_ID}
AWS_REGION={AWS_COGNITO_REGION_HERE}
CLIENT_ID={COGNITO_CLIENT_ID_HERE}
CLIENT_SECRET={COGNITO_CLIENT_SECRET_HERE}
POOL_ID={COGNITO_POOL_ID_HERE}
```

## Example usages

### Instructions
Copy into a `main.go`, or any `GO` file really, and pick an `awsnito` function from below, uncomment it and its corresponding variables.

```go
package main

import (
	"github.com/d-pollard/go-shove/awsnito"
	"fmt"
)

func main() {

	//user    := "some_user"
	//pass    := "A124345jkkj4!"
	//newPass := "_A124345jkkj4!"
	//email   := "joeshmoe@example.com"
	//name    := "Joe Shmoe"
	//code    := ""
	//jwtStr  := ""

	//a,b := awsnito.SignUp(user, pass, email, name)
	//a,b := awsnito.ConfirmSignUp(code, user)
	//a,b := awsnito.LogIn(user, pass)
	//a,b := awsnito.ValidateJwt(jwtStr)
	//a,b := awsnito.ForgotPassword(user)
	//a,b := awsnito.ConfirmForgotPassword(code, user, pass)
	//a,b := awsnito.ChangePassword(jwtStr, pass, newPass)

	if b != nil {
		panic(b)
	}

	fmt.Println(a)
}

```

