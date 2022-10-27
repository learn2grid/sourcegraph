package sourcegraphoperator

import (
	"net/http"
	"strings"
	"time"

	"github.com/inconshreveable/log15"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/auth"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/auth/providers"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/external/session"
	"github.com/sourcegraph/sourcegraph/enterprise/cmd/frontend/internal/auth/openidconnect"
	"github.com/sourcegraph/sourcegraph/internal/actor"
	"github.com/sourcegraph/sourcegraph/internal/database"
)

// All OpenID Connect endpoints are under this path prefix.
const authPrefix = auth.AuthURLPrefix + "/" + providerType

// Middleware is middleware for Sourcegraph Operator authentication, adding endpoints under the
// auth path prefix ("/.auth") to enable the login flow and requiring login for all other endpoints.
//
// 🚨SECURITY: See docstring of the openidconnect.Middleware for security details
// because the Sourcegraph Operator authentication provider is a wrapper of the
// OpenID Connect authentication provider.
//
// TODO(jchen): Init in enterprise/cmd/frontend/internal/auth/init.go once we
// have figured out how to only allow load SOAP from SRC_CLOUD_SITE_CONFIG, see
// https://github.com/sourcegraph/customer/issues/1427 for details.
func Middleware(db database.DB) *auth.Middleware {
	return &auth.Middleware{
		API: func(next http.Handler) http.Handler {
			// Pass through to the next handler for API requests.
			return next
		},
		App: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Fix up the URL path because we use "/.auth/callback" as the redirect URI for
				// Sourcegraph Operator, but the rest of handlers in this middleware expect paths
				// of "/.auth/sourcegraph-operator/...", so adding the "sourcegraph-operator"
				// path component as we can't change the redirect URI that it is hardcoded in
				// instances' external authentication providers.
				if r.URL.Path == auth.AuthURLPrefix+"/callback" {
					// Rewrite "/.auth/callback" -> "/.auth/sourcegraph-operator/callback".
					r.URL.Path = authPrefix + "/callback"
				}

				// Delegate to the Sourcegraph Operator authentication handler.
				if strings.HasPrefix(r.URL.Path, authPrefix+"/") {
					authHandler(db)(w, r)
					return
				}

				next.ServeHTTP(w, r)
			})
		},
	}
}

const SessionKey = "soap@0"
const stateCookieName = "sg-soap-state"

func authHandler(db database.DB) func(w http.ResponseWriter, r *http.Request) {
	getProvider := func(id string) *openidconnect.Provider {
		p, _ := providers.GetProviderByConfigID(
			providers.ConfigID{
				Type: providerType,
				ID:   id,
			},
		).(*provider)
		return p.Provider
	}
	return func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, authPrefix) {
		case "/login": // Endpoint that starts the Authentication Request Code Flow.
			p, safeErrMsg, err := openidconnect.GetProviderAndRefresh(r.Context(), r.URL.Query().Get("pc"), getProvider)
			if err != nil {
				log15.Error("Failed to get provider", "error", err)
				http.Error(w, safeErrMsg, http.StatusInternalServerError)
				return
			}
			openidconnect.RedirectToAuthRequest(w, r, p, stateCookieName, r.URL.Query().Get("redirect"))
			return

		case "/callback": // Endpoint for the OIDC Authorization Response, see http://openid.net/specs/openid-connect-core-1_0.html#AuthResponse.
			result, safeErrMsg, errStatus, err := openidconnect.AuthCallback(db, r, stateCookieName, "sourcegraph-operator-", getProvider)
			if err != nil {
				log15.Error("Failed to authenticate with Sourcegraph Operator", "error", err)
				http.Error(w, safeErrMsg, errStatus)
				return
			}

			p, _ := providers.GetProviderByConfigID(
				providers.ConfigID{
					Type: providerType,
					ID:   providerType,
				},
			).(*provider)

			// The user session will only live at most for the remaining duration from the
			// "users.created_at" compared to the current time.
			//
			// For example, if a Sourcegraph operator user account is created at
			// "2022-10-10T10:10:10Z" and the configured lifecycle duration is one hour, this
			// account will be deleted as early as "2022-10-10T11:10:10Z", which means:
			//   - Upon creation of an account, the session lives for an hour.
			//   - If the same operator signs out and signs back in again after 10 minutes,
			//       the second session only lives for 50 minutes.
			expiry := result.User.CreatedAt.Add(p.lifecycleDuration()).Sub(time.Now())
			if expiry <= 0 {
				http.Error(w, "The retrieved user account lifecycle has already expired, please re-authenticate.", http.StatusUnauthorized)
				return
			}
			if err = session.SetActor(w, r, actor.FromUser(result.User.ID), expiry, result.User.CreatedAt); err != nil {
				log15.Error("Failed to authenticate with Sourcegraph Operator: could not initiate session.", "error", err)
				http.Error(w, "Authentication failed. Try signing in again (and clearing cookies for the current site). The error was: could not initiate session.", http.StatusInternalServerError)
				return
			}

			if err = session.SetData(w, r, SessionKey, result.SessionData); err != nil {
				// It's not fatal if this fails. It just means we won't be able to sign the user
				// out of the OP.
				log15.Warn("Failed to set Sourcegraph Operator session data. The session is still secure, but Sourcegraph will be unable to revoke the user's token or redirect the user to the end-session endpoint after the user signs out of Sourcegraph.", "error", err)
			}

			if !result.User.SiteAdmin {
				err = db.Users().SetIsSiteAdmin(r.Context(), result.User.ID, true)
				if err != nil {
					log15.Error("Failed to update Sourcegraph Operator as site admin.", "error", err)
					http.Error(w, "Authentication failed. Try signing in again (and clearing cookies for the current site). The error was: could not set as site admin.", http.StatusInternalServerError)
					return
				}
			}

			// 🚨 SECURITY: Call auth.SafeRedirectURL to avoid the open-redirect vulnerability.
			http.Redirect(w, r, auth.SafeRedirectURL(result.Redirect), http.StatusFound)

		default:
			http.NotFound(w, r)
		}
	}
}
