package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-kit/kit/transport/http/jsonrpc"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/gorilla/feeds"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"
)

const (
	_ = jsonrpc.InternalError - iota

	// errCodeJWTInvalid is returned when a JWT is not able to be validated
	errCodeJWTInvalid
)

type service struct {
	origin             string
	browserExtensionID string
	str                storage
	web                *webauthn.WebAuthn
	sessionData        map[string]any
	sessionDataL       sync.Mutex
}

func (s *service) storeSessionData(k string, v any) {
	s.sessionDataL.Lock()
	defer s.sessionDataL.Unlock()

	// in order to keep this from being a memory leak over time, keep the
	// number of entries in the session below 5 by randomly deleting data
	// when it is too full.
	//
	// VULN: an attacker could just figure out a way to spam writes to session
	// data and impact workflows that depend on session data by continuously
	// making sure things are being constantly evicted
	for keys, i := maps.Keys(s.sessionData), 0; i < len(s.sessionData)-5; i++ {
		delete(s.sessionData, keys[i])
	}

	s.sessionData[k] = v
}

func (s *service) takeSessionData(k string) (any, bool) {
	s.sessionDataL.Lock()
	defer s.sessionDataL.Unlock()
	v, ok := s.sessionData[k]
	if ok {
		delete(s.sessionData, k)
	}
	return v, ok
}

type isInitializedResponse struct {
	Result             bool
	BrowserExtensionID string
}

func (s *service) isInitialized(ctx context.Context, _ struct{}) (isInitializedResponse, error) {
	sstate, err := s.str.state(ctx)
	if err != nil {
		return isInitializedResponse{}, errors.Wrap(err, "failed to check storage state")
	}
	return isInitializedResponse{
		Result:             sstate == initialized,
		BrowserExtensionID: s.browserExtensionID,
	}, nil
}

type webauthnUser struct {
	scs []storedCredential
}

// User ID according to the Relying Party
func (w webauthnUser) WebAuthnID() []byte {
	return []byte("76d6fa66-4756-4467-acaa-d7c288dfa0ea")
}

// User Name according to the Relying Party
func (w webauthnUser) WebAuthnName() string {
	return "main_user"
}

// Display Name of the user
func (w webauthnUser) WebAuthnDisplayName() string {
	return "Main User"
}

// User's icon url
func (w webauthnUser) WebAuthnIcon() string {
	return ""
}

// Credentials owned by the user
func (w webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return mapSlice(w.scs, func(sc storedCredential) webauthn.Credential {
		return *sc.Credential
	})
}

type webauthnRegBeginRequest struct {
	ConfigJWT string
}

type webauthnRegBeginResponse struct {
	RegSessionID              string                       `json:"regSessionID"`
	CredentialCreationOptions *protocol.CredentialCreation `json:"credentialCreationOptions"`
}

func (s *service) webauthnRegBegin(ctx context.Context, request webauthnRegBeginRequest) (webauthnRegBeginResponse, error) {
	xc, err := s.str.existingCredentials(ctx)
	if err != nil {
		return webauthnRegBeginResponse{}, errors.Wrap(err, "failed to retrieve existing webauthn credentials")
	}
	strstate, err := s.str.state(ctx)
	if err != nil {
		return webauthnRegBeginResponse{}, errors.Wrap(err, "failed to get storage state")
	}
	// only in this state is it okay to skip JWT verification since everything is
	// being bootstrapped in that state
	if strstate != waitForUserSetup {
		if err := s.validateAuthKey(ctx, request.ConfigJWT, configuring); err != nil {
			return webauthnRegBeginResponse{}, errors.WithStack(err)
		}
	}

	regSessionID := uuid.New().String()

	regoptions := []webauthn.RegistrationOption{
		webauthn.WithConveyancePreference(protocol.PreferDirectAttestation),
	}
	options, sessionData, err := s.web.BeginRegistration(webauthnUser{}, regoptions...)
	if err != nil {
		return webauthnRegBeginResponse{}, errors.Wrap(err, "failed to begin webauthn registration")
	}

	for _, c := range xc {
		options.Response.CredentialExcludeList = append(
			options.Response.CredentialExcludeList,
			protocol.CredentialDescriptor{
				CredentialID: []byte(c.Credential.ID),
				Type:         protocol.PublicKeyCredentialType,
			},
		)
	}

	s.storeSessionData(fmt.Sprintf("regSession-%s", regSessionID), sessionData)
	return webauthnRegBeginResponse{
		RegSessionID:              regSessionID,
		CredentialCreationOptions: options,
	}, nil
}

type webauthnRegFinishRequest struct {
	KeyName                    string          `json:"keyName"`
	RegSessionID               string          `json:"regSessionID"`
	CredentialCreationResponse json.RawMessage `json:"credentialCreationResponse"`
	IncludeNewJWT              bool            `json:"includeNewJWT"`
}

type webauthnRegFinishResponse struct {
	ConfiguringJWT string `json:"configuringJWT,omitempty"`
}

func takeSessionData[T any](s *service, key string) (T, bool) {
	v, ok := s.takeSessionData(key)
	if !ok {
		var zv T
		return zv, false
	}
	tv, ok := v.(T)
	return tv, ok
}

func (s *service) webauthnRegFinish(ctx context.Context, request webauthnRegFinishRequest) (webauthnRegFinishResponse, error) {
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(request.CredentialCreationResponse))
	if err != nil {
		return webauthnRegFinishResponse{}, errors.Wrap(err, "Failed to parse credential creation response")
	}
	sessionData, found := takeSessionData[*webauthn.SessionData](s, fmt.Sprintf("regSession-%s", request.RegSessionID))
	if !found {
		return webauthnRegFinishResponse{}, errors.New("unknown webauthn registration session")
	}

	credential, err := s.web.CreateCredential(webauthnUser{}, *sessionData, parsedResponse)
	if err != nil {
		return webauthnRegFinishResponse{}, errors.Wrap(err, "failed to create webauthn credential")
	}

	if err := s.str.storeCredential(ctx, request.KeyName, credential); err != nil {
		return webauthnRegFinishResponse{}, errors.Wrap(err, "failed to store webauthn credential")
	}

	out := webauthnRegFinishResponse{}
	if request.IncludeNewJWT {
		out.ConfiguringJWT, err = s.str.newAuthKey(ctx, configuring, time.Now().Unix()+60*60*12)
		if err != nil {
			return webauthnRegFinishResponse{}, errors.Wrap(err, "failed to issue new configuring jwt")
		}
	}
	return out, nil
}

type webauthnLoginBeginRequest struct{}
type webauthnLoginBeginResponse struct {
	LoginSessionID string
	Options        *protocol.CredentialAssertion
}

func (s *service) getWebauthnUser(ctx context.Context) (webauthn.User, error) {
	scs, err := s.str.existingCredentials(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get stored credentials")
	}
	return webauthnUser{scs: scs}, nil
}

func (s *service) webauthnLoginBegin(ctx context.Context, request webauthnLoginBeginRequest) (webauthnLoginBeginResponse, error) {
	wu, err := s.getWebauthnUser(ctx)
	if err != nil {
		return webauthnLoginBeginResponse{}, errors.Wrap(err, "failed to get stored credentials")
	}
	options, sessionData, err := s.web.BeginLogin(wu)
	if err != nil {
		return webauthnLoginBeginResponse{}, errors.Wrap(err, "failed to begin webauth login workflow")
	}
	loginSessionID := uuid.NewString()
	s.storeSessionData(fmt.Sprintf("loginSession-%s", loginSessionID), sessionData)
	return webauthnLoginBeginResponse{
		LoginSessionID: loginSessionID,
		Options:        options,
	}, nil
}

type webauthnLoginFinishRequest struct {
	LoginSessionID            string          `json:"loginSessionID"`
	CredentialRequestResponse json.RawMessage `json:"credentialRequestResponse"`

	// ForSaving is true if the webauthn request is for a saving token
	ForSaving bool `json:"forSaving"`
}
type webauthnLoginFinishResponse struct {
	JWT string
}

func (s *service) webauthnLoginFinish(ctx context.Context, request webauthnLoginFinishRequest) (webauthnLoginFinishResponse, error) {
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(request.CredentialRequestResponse))
	if err != nil {
		c := spew.NewDefaultConfig()
		c.DisableMethods = true
		c.Dump(err)
		return webauthnLoginFinishResponse{}, errors.Wrap(err, "failed to parse credential request response")
	}
	sessionData, found := takeSessionData[*webauthn.SessionData](s, fmt.Sprintf("loginSession-%s", request.LoginSessionID))
	if !found {
		return webauthnLoginFinishResponse{}, errors.New("unknown webauthn registration session")
	}
	wu, err := s.getWebauthnUser(ctx)
	if err != nil {
		return webauthnLoginFinishResponse{}, errors.Wrap(err, "failed to get stored credentials")
	}
	_, err = s.web.ValidateLogin(wu, *sessionData, parsedResponse)
	if err != nil {
		return webauthnLoginFinishResponse{}, errors.Wrap(err, "failed to validate webauthn login")
	}

	var use authKeyUse
	var expiry int64
	if request.ForSaving {
		use = saving
		const twoYears = 63_068_544
		expiry = time.Now().Unix() + twoYears
	} else {
		use = configuring
		expiry = time.Now().Unix() + 60*60*12
	}
	jwt, err := s.str.newAuthKey(ctx, use, expiry)
	if err != nil {
		return webauthnLoginFinishResponse{}, errors.Wrap(err, "failed to issue new configuring jwt")
	}
	return webauthnLoginFinishResponse{
		JWT: jwt,
	}, nil
}

type webauthnListKeysRequest struct {
	ConfigureJWT string
}

type webauthnListKeysResponse struct {
	Keys []webauthnListKeysResponseKey
}

type webauthnListKeysResponseKey struct {
	Name       string
	Descriptor protocol.CredentialDescriptor
}

func (s *service) validateAuthKey(ctx context.Context, authKey string, use authKeyUse) error {
	if err := s.str.validateAuthKey(ctx, authKey, use); err != nil {
		return jsonrpc.Error{
			Code:    errCodeJWTInvalid,
			Message: fmt.Sprintf("failed to verify auth key: %s", err.Error()),
		}
	}
	return nil
}

func (s *service) webauthnListKeys(ctx context.Context, request webauthnListKeysRequest) (webauthnListKeysResponse, error) {
	if err := s.validateAuthKey(ctx, request.ConfigureJWT, configuring); err != nil {
		return webauthnListKeysResponse{}, errors.WithStack(err)
	}
	xc, err := s.str.existingCredentials(ctx)
	if err != nil {
		return webauthnListKeysResponse{}, errors.Wrap(err, "failed to get stored credentials")
	}
	return webauthnListKeysResponse{
		Keys: mapSlice(xc, func(sc storedCredential) webauthnListKeysResponseKey {
			return webauthnListKeysResponseKey{
				Name: sc.Name,
				Descriptor: protocol.CredentialDescriptor{
					CredentialID: []byte(sc.Credential.ID),
					Type:         protocol.PublicKeyCredentialType,
				},
			}
		}),
	}, nil
}

func mapSlice[E, F any, S ~[]E](s S, mf func(E) F) []F {
	out := make([]F, 0, len(s))
	for i := range s {
		out = append(out, mf(s[i]))
	}
	return out
}

type genFeedURLRequest struct {
	ConfigureJWT string
}

func (s *service) genFeedURL(ctx context.Context, request genFeedURLRequest) (string, error) {
	if err := s.validateAuthKey(ctx, request.ConfigureJWT, configuring); err != nil {
		return "", errors.WithStack(err)
	}
	feedPW, err := s.str.getFeedPassword(ctx)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate auth key for saving")
	}
	return fmt.Sprintf("%s/feed.xml?authKey=%s", s.origin, feedPW), nil
}

type saveForLaterRequest struct {
	AuthKey string
	Title   string
	URL     string
	Note    string
}

func (s *service) saveForLater(ctx context.Context, request saveForLaterRequest) (struct{}, error) {
	if err := s.validateAuthKey(ctx, request.AuthKey, saving); err != nil {
		return struct{}{}, errors.WithStack(err)
	}
	err := s.str.saveForLater(ctx, storedEntry{
		Title:     request.Title,
		URL:       request.URL,
		Note:      request.Note,
		SavedDate: time.Now().UTC(),
	})
	return struct{}{}, errors.Wrap(err, "failed to save for later")
}

type getFeedRequest struct {
	Password string
}

func (s *service) getFeed(ctx context.Context, request getFeedRequest) (feeds.Feed, error) {
	feedPassword, err := s.str.getFeedPassword(ctx)
	if err != nil {
		return feeds.Feed{}, errors.Wrap(err, "failed to read feed password from storage")
	}
	if subtle.ConstantTimeCompare([]byte(feedPassword), []byte(request.Password)) != 1 {
		return feeds.Feed{}, errors.New("incorrect credentials")
	}
	feed := feeds.Feed{
		Title:       "RSSLater",
		Description: "A feed of all of the things on the Internet that you wanted to save for later",
		Link: &feeds.Link{
			Href: s.origin,
		},
	}
	ses, err := s.str.getStoredEntries(ctx)
	if err != nil {
		return feeds.Feed{}, errors.Wrap(err, "failed to get stored entries")
	}
	for i, se := range ses {
		if i == 0 {
			feed.Updated = se.SavedDate
		}
		feed.Items = append(feed.Items, &feeds.Item{
			Title: se.Title,
			Link: &feeds.Link{
				Href: se.URL,
			},
			Content: fmt.Sprintf("NOTE: %s", se.Note),
			Created: se.SavedDate,
		})
	}
	return feed, nil
}
