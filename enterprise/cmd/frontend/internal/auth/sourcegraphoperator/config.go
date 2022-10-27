package sourcegraphoperator

import (
	"context"
	"fmt"

	"github.com/sourcegraph/log"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/auth/providers"
	"github.com/sourcegraph/sourcegraph/internal/conf"
	"github.com/sourcegraph/sourcegraph/internal/conf/conftypes"
)

// TODO(jchen): Init in enterprise/cmd/frontend/internal/auth/init.go once we
// have figured out how to only allow load SOAP from SRC_CLOUD_SITE_CONFIG, see
// https://github.com/sourcegraph/customer/issues/1427 for details.
func Init() {
	conf.ContributeValidator(validateConfig)

	logger := log.Scoped(providerType, "Sourcegraph Operator config watch")
	go func() {
		conf.Watch(func() {
			var p providers.Provider
			for _, ap := range conf.Get().AuthProviders {
				if ap.SourcegraphOperator != nil {
					p = newProvider(*ap.SourcegraphOperator)
					break
				}
			}
			if p == nil {
				providers.Update(providerType, nil)
				return
			}

			go func() {
				if err := p.Refresh(context.Background()); err != nil {
					logger.Error("Error prefetching Sourcegraph Operator service provider metadata.", log.Error(err))
				}
			}()
			providers.Update(providerType, []providers.Provider{p})
		})
	}()
}

func validateConfig(c conftypes.SiteConfigQuerier) (problems conf.Problems) {
	loggedNeedsExternalURL := false
	seen := map[string]int{}
	for i, p := range c.SiteConfig().AuthProviders {
		if p.SourcegraphOperator == nil {
			continue
		}

		if j, ok := seen[providerType]; ok {
			problems = append(
				problems,
				conf.NewSiteProblem(fmt.Sprintf("Sourcegraph Operator authentication provider at index %d is duplicate of index %d, ignoring", i, j)),
			)
			continue
		}
		seen[providerType] = i

		if c.SiteConfig().ExternalURL == "" && !loggedNeedsExternalURL {
			problems = append(
				problems,
				conf.NewSiteProblem("Sourcegraph Operator authentication provider requires `externalURL` to be set to the external URL of your site (example: https://sourcegraph.example.com)"),
			)
			loggedNeedsExternalURL = true
			continue
		}
	}
	return problems
}
