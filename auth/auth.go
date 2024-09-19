package auth

import (
	"encoding/base64"
	"osvauld/config"
	"osvauld/infra/logger"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

type Claims struct {
	jwt.StandardClaims
	Username string `json:"username"`
	UserID   string `json:"token"`
}

// GenerateToken creates a JWT token for authenticated users.
func GenerateToken(username string, id uuid.UUID) (string, error) {
	jwtSecret := config.GetJWTSecret()
	// expiry time is 1 week
	expirationTime := time.Now().Add(7 * 24 * time.Hour)
	claims := &Claims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
		UserID: id.String(),
	}
	jwtSecretKey := []byte(jwtSecret)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		logger.Errorf(err.Error())
		return "", errors.Wrap(err, "GenerateToken failed")
	}
	return tokenString, nil
}

func VerifySignature(armoredSignature string, armoredPublicKey string, challenge string) (bool, error) {
	key, err := crypto.NewKeyFromArmored(armoredPublicKey)
	if err != nil {
		logger.Debugf("Error: reading key %v", err)
		return false, err
	}

	// Create a KeyRing from the Key
	pubKeyRing, err := crypto.NewKeyRing(key)
	if err != nil {
		logger.Debugf("Error: creating key ring %v", err)
		return false, err
	}

	// // Convert the challenge string to a *crypto.PlainMessage
	message := crypto.NewPlainMessageFromString(challenge)

	// Decode the armored signature
	decodedSig, _ := base64.StdEncoding.DecodeString(armoredSignature)

	signature, err := crypto.NewPGPSignatureFromArmored(string(decodedSig))
	if err != nil {
		logger.Debugf("Error: decoding signature %v", err)
		return false, err
	}

	// Verify the signature
	err = pubKeyRing.VerifyDetached(message, signature, crypto.GetUnixTime())
	if err != nil {
		logger.Debugf("Error: verifying signature %v", err)
		return false, err
	}

	return true, nil
}

func HashPassword(password string) (string, error) {
	// The second argument is the cost of hashing, which determines how much time is needed to calculate the hash.
	// The higher the cost, the more secure the hash, but the longer it will take to generate.
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

// CheckPasswordHash compares a hashed password with a plain password to check if they match.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
