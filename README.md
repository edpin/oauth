# Go OAuth

**This is work-in-progress.**

This simple package supports OAuth Authorization flow. It is very simple to use
and very small. If you're looking for a robust OAuth package with bells and
whistles, this is not it. I wrote it because I was curious to learn more about
OAuth and I also found others to be overly complex. This does what I need and
works well with Tradier Brokerage (I have not tested with other providers).

To use, first obtain a client ID and a client secret from an OAuth provider. Set
the callback uri you want to support (what your server will answer when the
provider calls) with the provider. Then get their two endpoints, authorize URL
and token URL. Then:

```
const (
    oauthBase    = "https://oauth.example.com/"
    clientID     = "..."
    clientSecret = "..."
)

auth = oauth.New(clientID, clientSecret, oauthBase+"oauth/authorize", oauthBase+"oauth/accesstoken")

mux := http.NewServeMux()
mux.Handle("/auth/callback", auth)
mux.HanldeFunc("/login", func(w http.ResponseWriter, r *http.Request) {
	const loginForm = `
<html>
<body>
<a href="%s">Login</a>
</body>
</html>
`
	user := oauth.UserName(r.RemoteAddr)  // Or pick a better UserName.
	url, err := auth.AuthorizeURL(user, []string{"read"}, "/logged")
	if err != nil {
	    w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("Something went wrong: %s", err)))
		return
	}
	w.Write([]byte(fmt.Sprintf(loginForm, url)))
})

// Start your server or use github.com/edpin/https:
https.StartSecureServer(mux, nil)
```
