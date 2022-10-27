package sourcegraphoperator

import (
	"time"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/auth/providers"
	"github.com/sourcegraph/sourcegraph/enterprise/cmd/frontend/internal/auth/openidconnect"
	"github.com/sourcegraph/sourcegraph/schema"
)

const providerType = "sourcegraph-operator"

// provider is the implementation of Sourcegraph Operator authentication
// provider for providers.Provider.
type provider struct {
	config schema.SourcegraphOperatorAuthProvider
	*openidconnect.Provider
}

// newProvider creates and returns a new Sourcegraph Operator authentication
// provider using the given config.
func newProvider(config schema.SourcegraphOperatorAuthProvider) providers.Provider {
	allowSignUp := true
	return &provider{
		config: config,
		Provider: openidconnect.NewProvider(
			schema.OpenIDConnectAuthProvider{
				AllowSignup:        &allowSignUp,
				ClientID:           config.ClientID,
				ClientSecret:       config.ClientSecret,
				ConfigID:           providerType,
				DisplayName:        "Sourcegraph Operators",
				Issuer:             config.Issuer,
				RequireEmailDomain: "sourcegraph.com",
				Type:               providerType,
			},
			authPrefix,
		).(*openidconnect.Provider),
	}
}

// ConfigID implements providers.Provider.
func (p *provider) ConfigID() providers.ConfigID {
	return providers.ConfigID{
		Type: providerType,
		ID:   providerType,
	}
}

// Config implements providers.Provider.
func (p *provider) Config() schema.AuthProviders {
	return schema.AuthProviders{
		SourcegraphOperator: &p.config,
	}
}

func (p *provider) lifecycleDuration() time.Duration {
	if p.config.LifecycleDuration <= 0 {
		return 60 * time.Minute
	}
	return time.Duration(p.config.LifecycleDuration) * time.Minute
}
