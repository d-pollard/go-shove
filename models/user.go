package models

type AuthenticatedUser struct {
	// Token           *jwt.Token
	Username        string
	AuthTime        float64
	TokenExpireTime float64
	TokenUse        string
	Level           string
	ClientAppID     string
	UUID            string
	IsTokenValid    bool
}
