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
import (
    "fmt"
    "net/http"

    "github.com/edpin/https"
    "github.com/edpin/oauth"
)

const (
    oauthBase    = "https://oauth.example.com/"
    providerName = "Some OAuth Provider"
    clientID     = "..."
    clientSecret = "..."
)

func main() {
   auth = oauth.New(providerName, clientID, clientSecret,
                    oauthBase+"oauth/authorize", oauthBase+"oauth/accesstoken",
                    oauthBase+"oauth/refreshtoken")

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

    // Consume all login notifications.
    go func(notifications chan *oauth.User) {
        for {
            user := <- notifications
            log.Printf("User %s authorized.", user.UserName)
        }
    }(auth.Login)

    // Start your server or use github.com/edpin/https:
    https.StartSecureServer(mux, nil)
}
```

To deal with refreshes, if your provided returned a RefreshToken for your users,
simply call `user.RefreshAccessTokenIfNeeded()` before each time you need an
access token for that user.

TODOs:

1. Use a small pool of HTTPS clients instead of creating a new one every time.
