package iriscaptchago

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"log"

	"github.com/dgrijalva/jwt-go"
)

//validationUrl :  is where the http request sent to
const validationUrl = `https://captcha.irisdev.net/check`
const IrisDevServer = `https://captcha.irisdev.net`

var (
	// ErrHandlerTimeout = http.ErrHandlerTimeout
	ErrSignatureInvalid = jwt.ErrSignatureInvalid
	ErrMisMachIP        = errors.New("the IPs are not matched")
	ErrInvalidSecret    = errors.New("Invalid Secret")
)

// UserResponse : the standard defined for User Response
type UserResponse struct {
	Success  bool   `json:"success"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	jwt.StandardClaims
}

// irisDev : the response Struct that resives from irisdev server
type irisServerResponse struct {
	Code    int    `json:"Code"`    // the Error Code 200 is OK / others shows Error - Note With Upper Case
	Message string `json:"Message"` // error Message - Note with Upper Case

	Hostname string `json:"hostname"` // the hostname of the site where the Iris-Captcha was solved
	Success  bool   `json:"success"`  // true | false
}

// The Global Handler
type IrisCaptchaHandler interface {
	GetJs() string
	Validate(string, string) (UserResponse, error)
}

/**
 * NewIrisCaptchaHandler
 * Create a new Handle
 *
 *
 */
func NewIrisCaptchaHandler(secret string) (IrisCaptchaHandler, error) {
	h := new(irisCaptchaHandler)
	var err error

	h.provider = IrisDevServer
	err = h.init(secret)
	return h, err
}

/**
 * NewIrisCaptchaHandlerRemote
 * Create a new Handle that the server is not hosted on iris dev - Premium Service
 *
 *
 */
func NewIrisCaptchaHandlerRemote(provider string) (IrisCaptchaHandler, error) {
	h := new(irisCaptchaHandler)
	var err error
	h.provider = provider
	h.selfHosted = true
	err = h.init("")
	return h, err
}

// irisCaptchaHandler the main Handler Object
type irisCaptchaHandler struct {
	secret string
	appUid string

	provider   string
	selfHosted bool

	js string

	publicKeyUpdateTime time.Time
	publicKey           *rsa.PublicKey
	hasValidPublicKey   bool

	sync.Mutex
}

//init :
func (c *irisCaptchaHandler) init(secret string) error {

	if !c.selfHosted {
		c.secret = secret
		ss := strings.Split(secret, "0x")
		if len(ss) < 2 {
			return ErrInvalidSecret
		}
		c.appUid = "0x" + ss[len(ss)-1]
	}
	if err := c.loadPublicKey(); err != nil {
		log.Printf("Couldn't Load Public-Key From %s , Using request mode\n", c.provider)
		log.Panic(err)
	}

	c.js = fmt.Sprintf(`<script src="https://captcha.irisdev.net/js/%s></script>`, c.appUid)
	return nil
}

//loadPublicKey :
func (c *irisCaptchaHandler) loadPublicKey() error {
	c.Lock()
	resp, err := http.Get(c.provider + "/publickey")
	if err != nil {
		c.Unlock()
		return err
	}
	defer resp.Body.Close()
	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.Unlock()
		return err
	}

	pembock, _ := pem.Decode([]byte(bs))

	i, err := x509.ParsePKIXPublicKey(pembock.Bytes)
	if err != nil {
		c.Unlock()
		return err
	}
	c.publicKey = i.(*rsa.PublicKey)
	c.Unlock()
	return nil
}

//GetJs :
func (c *irisCaptchaHandler) GetJs() string {
	return c.js
}

//Validate :
func (c *irisCaptchaHandler) Validate(userResponse string, remoteip string) (UserResponse, error) {
	var err error
	ur := UserResponse{}
	if c.hasValidPublicKey {
		// ready for using RSA Method
		ur, err := c.validateSig(userResponse, remoteip)
		if err != nil {
			if err == ErrSignatureInvalid && c.publicKeyUpdateTime.After(time.Now().Add(-5*time.Minute)) {
				return c.validateReq(userResponse, remoteip)
			}
			return ur, err
		}
	} else {
		// Using Request Mode
		return c.validateReq(userResponse, remoteip)
	}

	return ur, err
}

//validateSig : validate the user response using public-key
func (c *irisCaptchaHandler) validateSig(userResponse, remoteIP string) (UserResponse, error) {
	var err error
	ur := UserResponse{}

	tkn, err := jwt.ParseWithClaims(userResponse, &ur, func(token *jwt.Token) (interface{}, error) {
		return c.publicKey, nil
	})
	if err != nil {
		ur.Success = false
		return ur, err
	}
	if !tkn.Valid {
		err = ErrSignatureInvalid
		ur.Success = false
		return ur, err
	}
	if remoteIP != "" {
		if ur.IP != remoteIP {
			err = ErrMisMachIP
			ur.Success = false
			return ur, err
		}
	}

	return ur, err
}
func (c *irisCaptchaHandler) TestValidateSig(t *testing.T) {
	ur, err := c.validateSig("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWNjZXNzIjp0cnVlLCJob3N0bmFtZSI6ImlyaXNkZXYubmV0IiwiaXAiOiIzNy41OS4xNzMuMjAiLCJleHAiOjE2MDUwMzE2NTcsImlhdCI6MTYwNTAzMTU5N30.KXk2VFUuE9YxyVZRlsEvT9wMYibXqp77WvF3nxRPnqSXA3gKaD6Pjm0UIP2HUkwD-sEW114q5HmSMrB2IGENoN5X4AUal5cmbKUisoCiAiM7JXHxmjqmBzUWG7P6dGSMDjWfKPQ46TMuyQMtyZmrOMcxIgL1gPRbzW7yrPZqPEOGySdr-DLi1NGBUR8y_SEHesP_romn4P3qBc3M7B183Oe0tYP6q0REKboNuRwfhnA7cnpcmCT-_dDV4TpLpIPJcIRW4uAuEDr9POTvBv_96iV7XzxyVnmrsf8bbfUUD0ZyhnP3eK8VDjtqrpCIBNP7Zwm_6VqqhGAioUcrgZfH8A", "")
	if err == nil {
		t.Errorf("got %v, want time expired", err)
	}
	if err == jwt.ErrSignatureInvalid {
		t.Errorf("got %v, want %v", err, nil)
	}
	if ur.Success == true {
		t.Errorf("got %v, want %v", ur.Success, false)
	}
}

//validateReq : validate the user response using requesting to irisdev server
func (c *irisCaptchaHandler) validateReq(userResponse, remoteIP string) (UserResponse, error) {
	var err error
	var res irisServerResponse
	ur := UserResponse{}

	// generate form data
	formData := url.Values{}
	formData.Add("response", userResponse)
	formData.Add("secret", c.secret) // your Secret provided in your panel at https://my.irisdev.net
	if remoteIP != "" {
		formData.Add("remoteip", remoteIP) // your Secret provided in your panel at https://my.irisdev.net
	}

	// send request to irisDev server
	resp, err := http.PostForm(validationUrl, formData)
	if err != nil {
		return ur, err
	}
	defer resp.Body.Close()
	// read irisDev response body
	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ur, err
	}

	err = json.Unmarshal(bs, &res)

	if err != nil {
		return ur, err
	}

	ur.Success = res.Success
	ur.Hostname = res.Hostname
	ur.IP = remoteIP
	return ur, err
}

func (c *irisCaptchaHandler) TestValidateReq(t *testing.T) {
	ur, err := c.validateReq("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWNjZXNzIjp0cnVlLCJob3N0bmFtZSI6ImlyaXNkZXYubmV0IiwiaXAiOiIzNy41OS4xNzMuMjAiLCJleHAiOjE2MDUwMzE2NTcsImlhdCI6MTYwNTAzMTU5N30.KXk2VFUuE9YxyVZRlsEvT9wMYibXqp77WvF3nxRPnqSXA3gKaD6Pjm0UIP2HUkwD-sEW114q5HmSMrB2IGENoN5X4AUal5cmbKUisoCiAiM7JXHxmjqmBzUWG7P6dGSMDjWfKPQ46TMuyQMtyZmrOMcxIgL1gPRbzW7yrPZqPEOGySdr-DLi1NGBUR8y_SEHesP_romn4P3qBc3M7B183Oe0tYP6q0REKboNuRwfhnA7cnpcmCT-_dDV4TpLpIPJcIRW4uAuEDr9POTvBv_96iV7XzxyVnmrsf8bbfUUD0ZyhnP3eK8VDjtqrpCIBNP7Zwm_6VqqhGAioUcrgZfH8A", "")
	if err != nil {
		t.Errorf("got %v, want %v", err, nil)
	}
	if ur.Success == true {
		t.Errorf("got %v, want %v", ur.Success, false)
	}
}
