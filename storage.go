package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// authKeyUse is used to describe the use for an auth key.
type authKeyUse int

func (a authKeyUse) String() string {
	switch a {
	case configuring:
		return "configuring"
	case saving:
		return "saving"
	case reading:
		return "reading"
	}
	return fmt.Sprintf("authKeyUse(%d)", a)
}

const (
	_ = authKeyUse(iota)

	// configuring is a JWT for using the web interface to configure stuff
	configuring

	// saving is a JWT that will be embedded in the extension just for saving
	// new things
	saving

	// reading is JWT that will be included on the RSS feed URL so that the RSS
	// reader can download new items
	reading
)

type storageLifecycle int

const (
	uninitialized = storageLifecycle(iota)
	waitForUserSetup
	initialized
)

type storage interface {
	init(ctx context.Context) error
	state(ctx context.Context) (storageLifecycle, error)

	storeCredential(ctx context.Context, keyName string, c *webauthn.Credential) error
	existingCredentials(ctx context.Context) ([]storedCredential, error)

	getFeedPassword(ctx context.Context) (string, error)
	newAuthKey(ctx context.Context, use authKeyUse, expiry int64) (string, error)
	validateAuthKey(ctx context.Context, authKey string, use authKeyUse) error
	revokeAllAuthKeys(ctx context.Context) error

	saveForLater(ctx context.Context, entry storedEntry) error
	getStoredEntries(ctx context.Context) ([]storedEntry, error)
}

type storedEntry struct {
	Title     string
	URL       string
	Note      string
	SavedDate time.Time
}

type storedCredential struct {
	Name       string
	Credential *webauthn.Credential
}

type jsonFileStorage struct {
	filename                string
	l                       sync.RWMutex
	key                     *rsa.PrivateKey
	authKeysNotIssuedBefore int64
	user                    jsonFSUser
	feedURLPassword         string
	entries                 []storedEntry
}

type jsonFSUser struct {
	credentials []jsonFSUserCredential
}

type jsonFSUserCredential struct {
	Name       string
	Credential *webauthn.Credential
}

func newJSONStorage(filename string) (storage, error) {
	s := &jsonFileStorage{
		filename: filename,
	}
	existingBytes, err := os.ReadFile(filename)
	if os.IsNotExist(err) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate private rsa key")
		}
		s.feedURLPassword = uuid.NewString()
		s.key = privKey
		s.authKeysNotIssuedBefore = time.Now().Unix()
		if err := s.persist(context.Background()); err != nil {
			return nil, errors.Wrap(err, "failed to persist json storage")
		}
		return s, nil
	} else if err != nil {
		return nil, errors.Wrap(err, "failed to read json storage file")
	}

	if err := s.hydrate(existingBytes); err != nil {
		return nil, errors.Wrap(err, "failed to hydrate in memory json storage")
	}

	return s, nil
}

var _ storage = (*jsonFileStorage)(nil)

func (j *jsonFileStorage) storeCredential(ctx context.Context, keyName string, c *webauthn.Credential) error {
	j.l.Lock()
	defer j.l.Unlock()
	j.user.credentials = append(j.user.credentials, jsonFSUserCredential{
		Name:       keyName,
		Credential: c,
	})
	return errors.WithStack(j.persist(ctx))
}

func (j *jsonFileStorage) existingCredentials(ctx context.Context) ([]storedCredential, error) {
	j.l.RLock()
	defer j.l.RUnlock()
	scs := []storedCredential{}
	for _, c := range j.user.credentials {
		scs = append(scs, storedCredential(c))
	}
	return scs, nil
}

func (j *jsonFileStorage) state(ctx context.Context) (storageLifecycle, error) {
	if len(j.user.credentials) == 0 {
		return waitForUserSetup, nil
	}
	return initialized, nil
}

func parsePrivKeyFromPEM(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.Errorf("invalid pem data")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func encodePrivKeyToPEM(k *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}

func (j *jsonFileStorage) init(ctx context.Context) error {
	j.l.Lock()
	defer j.l.Unlock()
	return nil
}

func (j *jsonFileStorage) getFeedPassword(ctx context.Context) (string, error) {
	return j.feedURLPassword, nil
}

const jwtUseClaim = "rsslater:use"

func (j *jsonFileStorage) newAuthKey(ctx context.Context, use authKeyUse, expiry int64) (string, error) {
	return j.issueJWT(ctx, use, expiry)
}

func (j *jsonFileStorage) issueJWT(ctx context.Context, use authKeyUse, expiry int64) (string, error) {
	j.l.RLock()
	defer j.l.RUnlock()
	claims := jwt.MapClaims{
		"iat":       time.Now().Unix(),
		jwtUseClaim: use,
	}
	if expiry > 0 {
		claims["exp"] = expiry
	}
	unsignedToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	authKey, err := unsignedToken.SignedString(j.key)
	if err != nil {
		return "", errors.Wrap(err, "failed to sign auth key jwt")
	}
	return authKey, nil
}

func (j *jsonFileStorage) validateAuthKey(ctx context.Context, authKey string, use authKeyUse) error {
	j.l.RLock()
	defer j.l.RUnlock()

	token, err := jwt.Parse(authKey, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &j.key.PublicKey, nil
	})
	if err != nil {
		return errors.Wrap(err, "failed to parse auth key jwt")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !token.Valid || !ok {
		return errors.New("invalid auth key")
	}
	signedUse, _ := claims[jwtUseClaim].(float64)
	if authKeyUse(signedUse) != use {
		return fmt.Errorf("expected %s for auth key use, got %s", use, authKeyUse(signedUse))
	}
	iat, ok := claims["iat"].(float64)
	if !ok {
		return fmt.Errorf("missing iat claim in jwt")
	}
	if int64(iat) <= j.authKeysNotIssuedBefore {
		return fmt.Errorf("auth key is revoked")
	}
	return nil
}

func (j *jsonFileStorage) revokeAllAuthKeys(ctx context.Context) error {
	j.l.Lock()
	defer j.l.Unlock()
	j.authKeysNotIssuedBefore = time.Now().Unix()
	return errors.Wrap(j.persist(ctx), "failed to persist json state to disk")
}

func (j *jsonFileStorage) saveForLater(ctx context.Context, entry storedEntry) error {
	j.l.Lock()
	defer j.l.Unlock()
	j.entries = append([]storedEntry{entry}, j.entries...)
	return errors.Wrap(j.persist(ctx), "failed to persist json state to disk")
}

func (j *jsonFileStorage) getStoredEntries(ctx context.Context) ([]storedEntry, error) {
	j.l.RLock()
	defer j.l.RUnlock()
	return j.entries, nil
}

type jsonOnDiskStructure struct {
	Version int
	Data    json.RawMessage
}

type jsonOnDiskV1DataStructure struct {
	PrivKeyPEM             string
	AuthKeyNotIssuedBefore int64
	User                   jsonOnDiskV1DataStructureUser
	Entries                []jsonOnDiskV1DataStructureEntry
}

type jsonOnDiskV1DataStructureUser struct {
	FeedURLPassword string
	Credentials     []jsonFSUserCredential
}

type jsonOnDiskV1DataStructureEntry storedEntry

func (j *jsonFileStorage) hydrate(data []byte) error {
	var c jsonOnDiskStructure
	if err := json.Unmarshal(data, &c); err != nil {
		return errors.Wrap(err, "failed to json decode container structure of json storage")
	}
	if c.Version != 1 {
		return fmt.Errorf("expected version to be 1, got %d", c.Version)
	}
	var d jsonOnDiskV1DataStructure
	if err := json.Unmarshal(c.Data, &d); err != nil {
		return errors.Wrap(err, "failed to json decode v1 data structure of json storage")
	}

	j.l.Lock()
	defer j.l.Unlock()
	privKey, err := parsePrivKeyFromPEM(d.PrivKeyPEM)
	if err != nil {
		return errors.Wrap(err, "invalid rsa key in stored file")
	}

	j.key = privKey
	j.user.credentials = d.User.Credentials
	j.feedURLPassword = d.User.FeedURLPassword
	j.entries = mapSlice(d.Entries, func(de jsonOnDiskV1DataStructureEntry) storedEntry {
		return storedEntry(de)
	})
	return nil
}

func (j *jsonFileStorage) persist(ctx context.Context) error {
	ddata, err := json.Marshal(jsonOnDiskV1DataStructure{
		PrivKeyPEM:             encodePrivKeyToPEM(j.key),
		AuthKeyNotIssuedBefore: j.authKeysNotIssuedBefore,
		User: jsonOnDiskV1DataStructureUser{
			FeedURLPassword: j.feedURLPassword,
			Credentials:     j.user.credentials,
		},
		Entries: mapSlice(j.entries, func(se storedEntry) jsonOnDiskV1DataStructureEntry {
			return jsonOnDiskV1DataStructureEntry(se)
		}),
	})
	if err != nil {
		return errors.Wrap(err, "failed to encode json data structure")
	}

	cdata, err := json.Marshal(jsonOnDiskStructure{
		Version: 1,
		Data:    ddata,
	})
	if err != nil {
		return errors.Wrap(err, "failed to encode json container structure")
	}

	return errors.Wrap(os.WriteFile(j.filename, cdata, 0666), "failed to write json file")
}
