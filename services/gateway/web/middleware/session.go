package middleware

import (
	"net/http"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
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
	onlyoffice  *shared.OnlyofficeConfig
	logger      log.Logger
}

func NewSessionMiddleware(
	jwtManager crypto.JwtManager,
	store *sessions.CookieStore,
	credentials *oauth2.Config,
	onlyoffice *shared.OnlyofficeConfig,
	logger log.Logger,
) SessionMiddleware {
	return SessionMiddleware{
		jwtManager:  jwtManager,
		store:       store,
		credentials: credentials,
		onlyoffice:  onlyoffice,
		logger:      logger,
	}
}

func (m SessionMiddleware) saveRedirectURL(rw http.ResponseWriter, r *http.Request) {
	session, _ := m.store.Get(r, "url")
	session.Values["redirect"] = m.onlyoffice.Onlyoffice.Builder.GatewayURL + r.URL.String()
	session.Save(r, rw)
}

func (m SessionMiddleware) Protect(next http.Handler) http.Handler {
	fn := func(rw http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user")
		session, _ := m.store.Get(r, "onlyoffice-auth")
		val, ok := session.Values["token"].(string)
		if !ok {
			m.logger.Debug("could not cast token to string")
			session.Options.MaxAge = -1
			session.Save(r, rw)
			m.saveRedirectURL(rw, r)
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		r.Header.Set("Locale", "en")
		if loc, ok := session.Values["locale"].(string); ok {
			r.Header.Set("Locale", loc)
		}

		var token jwt.MapClaims
		if err := m.jwtManager.Verify(m.credentials.ClientSecret, val, &token); err != nil {
			m.logger.Debugf("could not verify session token: %s", err.Error())
			session.Options.MaxAge = -1
			session.Save(r, rw)
			m.saveRedirectURL(rw, r)
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		if token["jti"] != userID {
			m.logger.Debugf("user %s doesn't match state user %s", token["jti"], userID)
			session.Options.MaxAge = -1
			session.Save(r, rw)
			m.saveRedirectURL(rw, r)
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
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
