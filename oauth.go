// Copyright 2017 Eduardo Pinheiro (edpin@edpin.com). All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/edpin/https"
)

// UserName is a string that identifies a user. It's opaque to this package and
// is only used for associating an access token with some account. Examples of
// useful user names are email addresses, user IDs, actual user names, etc.
type UserName string

// User represents a user and holds the UserName and AccessToken.
type User struct {
	UserName     UserName  // User's name.
	AccessToken  string    // User's access token.
	RefreshToken string    // Token to refresh the access token.
	Expiration   time.Time // Time the access token expires, in UTC.
	Scopes       []string  // Scopes granted to the access token.

	next string // next URL to show this user once authorized.
	code string // authorization code.

	oauth *OAuth // the OAuth object that "owns" this user.
}

// OAuth is an HTTP.Handler that handles the OAuth dance.
type OAuth struct {
	// Login is a buffered channel that receives notifications when new auth
	// requests succeed. If the buffer fills up, further notifications are
	// dropped until the channel has buffer space again.
	Login chan *User

	errTpl       *template.Template
	clientID     string
	clientSecret string
	authorizeURL string
	tokenURL     string
	refreshURL   string

	mu           sync.Mutex // protects the fields below.
	users        map[UserName]*User
	usersByState map[authState]*User
}

var ErrNotFound = errors.New("Username not found")

type authState string

// New creates an OAuth client with a clientID and clientSecret as given. The
// endpoint for retrieving an authorization code is given by the authorizeURL.
// The endpoint for retrieving an access token is given by the tokenURL. Both
// endpoints must be fully specified (i.e. the full URL starting with
// "https://").
func New(clientID, clientSecret, authorizeURL, tokenURL, refreshURL string) *OAuth {
	return &OAuth{
		Login: make(chan *User, 100),
		errTpl: template.Must(template.New("errTpl").Parse(`
			<html>
			<body>
			<h1>{{.ErrorCode}}</h1>
			<p>{{.ErrorMsg}}</p>
			</body>
			</html>
		`)),
		clientID:     clientID,
		clientSecret: clientSecret,
		authorizeURL: authorizeURL,
		tokenURL:     tokenURL,
		refreshURL:   refreshURL,
		users:        make(map[UserName]*User),
		usersByState: make(map[authState]*User),
	}
}

// RegisterCallbackHandler is a convenience function that associates a given
// access pattern on the given HTTP server with the registration callback. This
// pattern must be the same one registered with the OAuth service provider for
// this application. For example, "/auth", "/auth/callback". The HTTP server
// parameter may be nil, in which case the pattern is registered with the
// default HTTP server.
func (o *OAuth) RegisterCallbackHandler(pattern string, httpServer *http.ServeMux) {
	if httpServer == nil {
		httpServer = http.DefaultServeMux
	}
	httpServer.Handle(pattern, o)
}

// AuthorizeURL returns a URL that can be rendered for users to authenticate
// themselves and obtain authorization for the scopes listed. An opaque user
// name or ID is given so this server can associate the user with the authorized
// key. Once authorized, the user is redirected to the nextURL (if it's empty,
// the user will see a debug message).
func (o *OAuth) AuthorizeURL(u UserName, scopes []string, nextURL string) (*url.URL, error) {
	const op = "oauth.AuthorizeURL"

	if len(scopes) == 0 {
		return nil, fmt.Errorf("%s: at least one scope must be provided", op)
	}
	scopeList := strings.Join(scopes, ",")
	var buf [8]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		return nil, err
	}
	state := authState(fmt.Sprintf("%x", buf))
	o.mu.Lock()
	o.usersByState[state] = &User{
		UserName: u,
		next:     nextURL,
		oauth:    o,
	}
	o.mu.Unlock()
	return url.Parse(fmt.Sprintf("%s?client_id=%s&scope=%s&state=%s", o.authorizeURL, o.clientID, scopeList, state))
}

// User returns the known facts about the given user or ErrNotFound if the user
// is not known or has dropped off the cache.
func (o *OAuth) User(u UserName) (*User, error) {
	if user, found := o.users[u]; found {
		return user, nil
	}
	return nil, ErrNotFound
}

// RefreshAccessTokenIfNeeded refreshes the access token if the user has a
// refresh token and the access token is close to expiring. This may do a
// network request. Upon successful return, a call to User is guaranteed to
// yield the refreshed token. It does not generate an event on the login
// channel.
func (u *User) RefreshAccessTokenIfNeeded() error {
	const op = "oauth.RefreshIfNeeded"

	// Do we still have 1 hour left in this token?
	if u.Expiration.Add(1 * time.Hour).After(time.Now().UTC()) {
		return nil
	}
	// Must refresh, if we have a refresh token.
	return u.RefreshAccessToken()
}

// RefreshAccessToken makes a network call to refresh the access token, if this
// user has a refresh token.
func (u *User) RefreshAccessToken() error {
	const op = "oauth.RefreshToken"

	if len(u.RefreshToken) == 0 {
		return fmt.Errorf("No refresh token for user %s", u.UserName)
	}

	data := bytes.NewBufferString(fmt.Sprintf("grant_type=refresh_token&refresh_token=%s", u.RefreshToken))
	req, err := http.NewRequest("POST", u.oauth.refreshURL, data)
	if err != nil {
		return fmt.Errorf("%s: Error creating request: %s", op, err)
	}
	req.SetBasicAuth(u.oauth.clientID, u.oauth.clientSecret)
	resp, err := doReq(req) // Safe, uses HTTPS.
	if err != nil {
		return fmt.Errorf("getting token from %s: %s", u.oauth.refreshURL, err)
	}

	var tr tokenResponse
	err = json.Unmarshal(resp, &tr)
	if err != nil {
		return fmt.Errorf("unmarshaling refresh token response: %s", err)
	}
	if tr.Status != "approved" {
		return fmt.Errorf("not approved by server: %s", tr.Status)
	}
	if tr.Token == "" {
		return fmt.Errorf("no access token present in response")
	}
	if tr.RefreshToken != "" {
		u.RefreshToken = tr.RefreshToken
	}
	u.AccessToken = tr.Token
	u.Expiration = time.Now().Add(time.Duration(tr.ExpiresSec) * time.Second).UTC()
	u.Scopes = strings.Split(tr.Scope, " ")
	return nil
}

// SetErrorTemplate sets a template for returning error pages to the user when
// the registered callback is called with the wrong parameters. This is only
// relevant in a few cases: 1) if you expect someone will accidentally visit
// the callback URL; 2) if the user declines to authorize and hence can't
// continue to nextURL (set by AuthorizeURL); 3) the provider makes an invalid
// call or a very delayed call and there's no longer a context for the user.
//
// Setting an error template is optional. A simple one is provided by default.
//
// The error template can make use of two fields ".ErrorMsg" for a short error
// message  and ".ErrorCode" which is the HTTP error code (int) being
// returned. The error template can only be set before registering OAuth with an
// HTTP server (i.e. before using it for the first time). The template must not
// be changed afterwards (Clone it first if subsequent changes are planned).
func (o *OAuth) SetErrorTemplate(errTpl *template.Template) {
	o.errTpl = errTpl
}

type tokenResponse struct {
	Token        string `json:"access_token"`
	ExpiresSec   int64  `json:"expires_in"`
	IssueDateStr string `json:"issued_at"`
	RefreshToken string `json:"refresh_token"`
	Scope        string
	Status       string
}

// ServeHTTP implements http.Handler. It handles the callback response from the
// OAuth provider as registered by RegisterCallbackHandler. This should not be
// called directly; it is used by the HTTP server.
func (o *OAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const op = "OAuth.ServeHTTP"

	q := r.URL.Query()
	code := q.Get("code")
	state := authState(q.Get("state"))
	o.mu.Lock()
	userData, found := o.usersByState[state]
	if !found {
		o.mu.Unlock()
		o.sendError(fmt.Errorf("Invalid state: %s", state), http.StatusForbidden, w)
		return
	}
	delete(o.usersByState, state)
	o.mu.Unlock()

	// Make a call to the tokenURL and give it our authorization code we
	// just obtained.
	data := strings.NewReader("grant_type=authorization_code&code=" + code)
	req, err := http.NewRequest("POST", o.tokenURL, data)
	if err != nil {
		log.Printf("%s: Error creating request: %s", op, err)
		o.sendError(err, http.StatusInternalServerError, w)
		return
	}
	req.SetBasicAuth(o.clientID, o.clientSecret)
	resp, err := doReq(req) // Safe, uses HTTPS.
	if err != nil {
		err = fmt.Errorf("getting token from %s: %s", o.tokenURL, err)
		log.Printf("%s: %s", op, err)
		o.sendError(err, http.StatusInternalServerError, w)
		return
	}

	var tr tokenResponse
	err = json.Unmarshal(resp, &tr)
	if err != nil {
		log.Printf("%s: %s", op, err)
		o.sendError(err, http.StatusInternalServerError, w)
	}
	userData.AccessToken = tr.Token
	userData.RefreshToken = tr.RefreshToken
	userData.Expiration = time.Now().Add(time.Duration(tr.ExpiresSec) * time.Second).UTC()
	userData.Scopes = strings.Split(tr.Scope, " ")

	// Notify of new login.
	select {
	case o.Login <- userData:
		// Done.
	default:
		log.Printf("Login channel full. Drain faster.")
	}
	// If there's no next URL, render an ugly message on the current page.
	if userData.next == "" {
		w.Write([]byte(fmt.Sprintf("User %s authorized", userData.UserName)))
		return
	}
	w.Header().Set("Location", userData.next)
	w.WriteHeader(http.StatusTemporaryRedirect)
}

// sendError attempts to send an error on the error channel and if the caller is
// not fast enough, it renders an error message to the remote addrs.
func (o *OAuth) sendError(e error, status int, w http.ResponseWriter) {
	data := struct {
		ErrorCode int
		ErrorMsg  string
	}{
		ErrorCode: status,
		ErrorMsg:  e.Error(),
	}
	w.WriteHeader(status)
	err := o.errTpl.Execute(w, data)
	if err != nil {
		log.Printf("Couldn't render error template: %s", err)
	}
}

func doReq(req *http.Request) ([]byte, error) {
	req.Header.Add("Accept", "application/json")
	client := https.NewClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Request failed: %s (%d)", resp.Status, resp.StatusCode)
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}
