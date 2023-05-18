package middleware

import (
	"net/http"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/pkg/crypto"
	"github.com/ONLYOFFICE/onlyoffice-box/pkg/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

func NewSessionStore(credentials *oauth2.Config) *sessions.CookieStore {
	return &sessions.CookieStore{
		Codecs: securecookie.CodecsFromPairs([]byte(credentials.ClientSecret)),
		Options: &sessions.Options{
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   86400 * 30,
			SameSite: http.SameSiteNoneMode,
		},
	}
}

type SessionMiddleware struct {
	jwtManager  crypto.JwtManager
	store       *sessions.CookieStore
	credentials *oauth2.Config
	logger      log.Logger
}

func NewSessionMiddleware(
	jwtManager crypto.JwtManager,
	store *sessions.CookieStore,
	credentials *oauth2.Config,
	logger log.Logger,
) SessionMiddleware {
	return SessionMiddleware{
		jwtManager:  jwtManager,
		store:       store,
		credentials: credentials,
		logger:      logger,
	}
}

func (m SessionMiddleware) Protect(next http.Handler) http.Handler {
	fn := func(rw http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user")
		session, err := m.store.Get(r, "onlyoffice-auth")
		if err != nil {
			m.logger.Errorf("could not get session for user %s: %s", userID, err.Error())
			http.Redirect(rw, r, "/oauth/auth", http.StatusMovedPermanently)
			return
		}

		val, ok := session.Values["token"].(string)
		if !ok {
			m.logger.Debug("could not cast token to string")
			session.Options.MaxAge = -1
			session.Save(r, rw)
			http.Redirect(rw, r, "/oauth/auth", http.StatusMovedPermanently)
			return
		}

		var token jwt.MapClaims
		if err := m.jwtManager.Verify(m.credentials.ClientSecret, val, &token); err != nil {
			m.logger.Debugf("could not verify session token: %s", err.Error())
			session.Options.MaxAge = -1
			session.Save(r, rw)
			http.Redirect(rw, r, "/oauth/auth", http.StatusMovedPermanently)
			return
		}

		if token["jti"] != userID {
			m.logger.Debugf("user %s doesn't match state user %s", token["jti"], userID)
			session.Options.MaxAge = -1
			session.Save(r, rw)
			http.Redirect(rw, r, "/oauth/auth", http.StatusMovedPermanently)
			return
		}

		signature, _ := m.jwtManager.Sign(m.credentials.ClientSecret, jwt.RegisteredClaims{
			ID:        userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * 7 * time.Hour)),
		})

		session.Values["token"] = signature
		session.Options.MaxAge = 60 * 60 * 23 * 7
		if err := session.Save(r, rw); err != nil {
			m.logger.Errorf("could not save session token: %s", err.Error())
		}

		m.logger.Debugf("refreshed current session: %s", signature)

		next.ServeHTTP(rw, r)
	}

	return http.HandlerFunc(fn)
}
