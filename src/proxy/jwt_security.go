package proxy

import (
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type JwtSignatureTool interface {
	GetPublicKey(key string) ([]byte, error)
	SignToken(claims jwt.Claims) (string, error)
	GetJWT(token string) (*jwt.Token, error)
}

func NewSignatureTool(conf Config) JwtSignatureTool {
	if conf.Security.SymetricSignature {
		return newJwtHSSignatureTool(conf.Security.JWTSecret)
	}
	return newJwtRSASignatureTool(conf.Security.KeysFolder)
}

type kid string

type pathKeys struct {
	pathPrivateKey string
	pathPublicKey  string
	kid            kid
}

func (pk pathKeys) Valid() bool {
	return pk.kid != "" && pk.pathPublicKey != ""
}

type JwtSymetricSignatureTool struct {
	hs256SecretKey []byte
}

type JwtAsymetricSignatureTool struct {
	keys       map[kid]pathKeys
	currentKey kid
}

func newJwtHSSignatureTool(secret string) JwtSignatureTool {
	return JwtSymetricSignatureTool{hs256SecretKey: []byte(secret)}
}

func (j JwtSymetricSignatureTool) GetPublicKey(key string) ([]byte, error) {
	// Not implemented for symetric, return classic secret
	return j.hs256SecretKey, nil
}

func (j JwtSymetricSignatureTool) SignToken(claims jwt.Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(j.hs256SecretKey)
}

func (j JwtSymetricSignatureTool) GetJWT(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) { return j.hs256SecretKey, nil })
}

// newJwtRSASignatureTool create a new instance of signature tool
// init run at beginning :
// Delete all previous private keys
// Generate with openssl new couple of RSA keys
// List public keys and compute kid
func newJwtRSASignatureTool(folder string) JwtSignatureTool {
	j := JwtAsymetricSignatureTool{}
	cleanOldPrivateKeys(folder)
	err := generateNewPairOfKey(folder)
	if err != nil {
		log.Println("ERROR", err)
	}
	j.keys, j.currentKey = listExistingKeys(folder)
	log.Println("Founded keys", len(j.keys))
	return j
}

func computeShortHashPublicKey(path string) kid {
	if f, err := os.Open(path); err == nil {
		data, _ := io.ReadAll(f)
		hash := sha1.Sum(data)
		return kid(base64.StdEncoding.EncodeToString(hash[:])[:5])
	} else {
		return ""
	}
}

func generateNewPairOfKey(folder string) error {
	d := time.Now()
	privateKeyPath := filepath.Join(folder, fmt.Sprintf("private_%s.key", d.Format("20060102150405")))
	publicKeyPath := filepath.Join(folder, fmt.Sprintf("public_%s.key", d.Format("20060102150405")))

	execPrivateKey := exec.Command("openssl", "genrsa", "-out", privateKeyPath, "2048")
	execPublicKey := exec.Command("openssl", "rsa", "-in", privateKeyPath, "-pubout", "-out", publicKeyPath)
	_, err := execPrivateKey.Output()
	if err != nil {
		return err
	}
	_, err = execPublicKey.Output()
	return err
}

func cleanOldPrivateKeys(folder string) {
	dir, err := os.Open(folder)
	if err != nil {
		return
	}
	counter := 0
	defer dir.Close()
	files, _ := dir.Readdir(-1)
	for _, file := range files {
		if !file.IsDir() && strings.HasPrefix(file.Name(), "private_") {
			if os.Remove(filepath.Join(folder, file.Name())) == nil {
				counter++
			}

		}
	}
	log.Println("Remove", counter, "key(s)")
}

func listExistingKeys(folder string) (map[kid]pathKeys, kid) {
	dir, err := os.Open(folder)
	if err != nil {
		return nil, ""
	}
	defer dir.Close()
	r, _ := regexp.Compile("((private)|(public))_([0-9]{14})\\.key")
	files, _ := dir.Readdir(-1)
	keysByDate := make(map[string]pathKeys)
	for _, file := range files {
		if !file.IsDir() {
			subs := r.FindAllStringSubmatch(file.Name(), -1)
			if len(subs) == 1 {
				date := subs[0][4]
				pk, exist := keysByDate[date]
				if !exist {
					pk = pathKeys{}
				}
				path := filepath.Join(folder, file.Name())
				switch subs[0][1] {
				case "private":
					pk.pathPrivateKey = path
				case "public":
					pk.pathPublicKey = path
					pk.kid = computeShortHashPublicKey(path)
				}
				keysByDate[date] = pk
			}
		}
	}
	// Key only pathkey with at least public key and kid
	results := make(map[kid]pathKeys)
	var currentKid kid
	for _, pk := range keysByDate {
		if pk.Valid() {
			results[kid(pk.kid)] = pk
			if pk.pathPrivateKey != "" {
				currentKid = pk.kid
			}
		}
	}
	return results, currentKid
}

func (j JwtAsymetricSignatureTool) getCurrentPrivateKey() *rsa.PrivateKey {
	if j.currentKey == "" {
		return nil
	}
	data, err := os.ReadFile(j.keys[j.currentKey].pathPrivateKey)
	if err != nil {
		return nil
	}
	token, _ := jwt.ParseRSAPrivateKeyFromPEM(data)
	return token
}

// SignToken return a signed token with the kid of signature
func (j JwtAsymetricSignatureTool) SignToken(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = j.currentKey
	return token.SignedString(j.getCurrentPrivateKey())
}

// GetPublicKey return a public key from a kid. If no key found, return an error
func (j JwtAsymetricSignatureTool) GetPublicKey(key string) ([]byte, error) {
	kp, exist := j.keys[kid(key)]
	if !exist {
		return []byte{}, errors.New("public key not found")
	}
	data, err := os.ReadFile(kp.pathPublicKey)
	return data, err
}

func (j JwtAsymetricSignatureTool) GetJWT(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		data, err := j.GetPublicKey(token.Header["kid"].(string))
		if err != nil {
			return nil, err
		}
		return jwt.ParseRSAPublicKeyFromPEM(data)
	})
}
