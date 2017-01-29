// Copyright 2017 Eduardo Pinheiro (edpin@edpin.com). All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth

import (
	"crypto/rand"
	"encoding/json"
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
	UserName    UserName  // User's name.
	AccessToken string    // User's access token.
	Expiration  time.Time // Time the access token expires, in UTC.
	Scopes      []string  // Scopes granted to the access token.

	next string // next URL to show this user once authorized.
	code string // authorization code.
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

	mu           sync.Mutex // protects the fields below.
	users        map[UserName]*User
	usersByState map[authState]*User
}

type authState string

// New creates an OAuth client with a clientID and clientSecret as given. The
// endpoint for retrieving an authorization code is given by the authorizeURL.
// The endpoint for retrieving an access token is given by the tokenURL. Both
// endpoints must be fully specified (i.e. the full URL starting with
// "https://").
func New(clientID, clientSecret, authorizeURL, tokenURL string) *OAuth {
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
// themselves and obtain authorization for the scopes listed. An opaque user name or ID is given so this server can associate
// the user with the authorized key. Once authorized, the user is redirected to
// the nextURL (if it's empty, the user will see a debug message).
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
	}
	o.mu.Unlock()
	return url.Parse(fmt.Sprintf("%s?client_id=%s&scope=%s&state=%s", o.authorizeURL, o.clientID, scopeList, state))
}

// SetErrorTemplate sets a template for returning error pages to the user.
// The template can make use of two fields ".ErrorMsg" for a short error
// message  and ".ErrorCode" which is the HTTP error code (int) being
// returned. If a template is not set, the default one is used, which prints the
// error message and code with little formatting. The error template can only be
// set before registering OAuth with an HTTP server (i.e. before using
// it for the first time). The template must not be changed afterwards (Clone it
// first if subsequent changes are planned).
func (o *OAuth) SetErrorTemplate(errTpl *template.Template) {
	o.errTpl = errTpl
}

type tokenResponse struct {
	Token        string `json:"access_token"`
	ExpiresSec   int64  `json:"expires_in"`
	IssueDateStr string `json:"issued_at"`
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
