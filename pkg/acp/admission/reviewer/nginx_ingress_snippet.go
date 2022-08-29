package reviewer

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/traefik/hub-agent-kubernetes/pkg/acp"
)

const (
	hubSnippetTokenStart = "##hub-snippet-start"
	hubSnippetTokenEnd   = "##hub-snippet-end"
)

type nginxSnippets struct {
	// Community snippets:
	AuthSignin           string
	AuthSnippet          string
	AuthURL              string
	ConfigurationSnippet string
	ServerSnippet        string
}

func genSnippets(polName string, polCfg *acp.Config, agentAddr string) (nginxSnippets, error) {
	headerToFwd, err := headerToForward(polCfg)
	if err != nil {
		return nginxSnippets{}, fmt.Errorf("get header to forward: %w", err)
	}

	locSnip := generateLocationSnippet(headerToFwd)

	nginxSnippet := nginxSnippets{
		AuthURL:              fmt.Sprintf("%s/%s", agentAddr, polName),
		ConfigurationSnippet: locSnip,
	}

	if polCfg.OIDC != nil {
		nginxSnippet.AuthSignin = "$url_redirect"
		nginxSnippet.AuthSnippet = `
proxy_set_header From nginx;
proxy_set_header X-Forwarded-Uri $request_uri;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Method $request_method;`
		nginxSnippet.ConfigurationSnippet += "auth_request /auth;"
		nginxSnippet.ConfigurationSnippet += " auth_request_set $url_redirect $upstream_http_url_redirect;"
		nginxSnippet.ConfigurationSnippet += " auth_request_set $cookie $upstream_http_set_cookie;"
		nginxSnippet.ConfigurationSnippet += " add_header Set-Cookie $cookie;"
		nginxSnippet.ConfigurationSnippet += " error_page 401 @oidc;"

		url, err := url.Parse(polCfg.OIDC.RedirectURL)
		if err != nil {
			return nginxSnippets{}, fmt.Errorf("parse redirect url: %w", err)
		}

		var redirectURL = "/callback"
		if url.Path != "" {
			redirectURL = polCfg.OIDC.RedirectURL
		}

		if redirectURL[0] != '/' {
			redirectURL = "/" + redirectURL
		}

		nginxSnippet.ServerSnippet = fmt.Sprintf("location %s { proxy_pass %s/%s; proxy_set_header X-Forwarded-Uri $request_uri; proxy_set_header X-Forwarded-Host $host; proxy_set_header X-Forwarded-Proto $scheme; }", redirectURL, agentAddr, polName)
		nginxSnippet.ServerSnippet += fmt.Sprintf("\nlocation /auth { %s proxy_pass %s; }", nginxSnippet.AuthSnippet, nginxSnippet.AuthURL)
		nginxSnippet.ServerSnippet += "\nlocation @oidc { add_header Set-Cookie $cookie; return 302 $url_redirect;}"
	}

	nginxSnippet.ConfigurationSnippet = wrapHubSnippet(nginxSnippet.ConfigurationSnippet)
	nginxSnippet.AuthSnippet = wrapHubSnippet(nginxSnippet.AuthSnippet)
	nginxSnippet.ServerSnippet = wrapHubSnippet(nginxSnippet.ServerSnippet)

	return nginxSnippet, nil
}

func generateLocationSnippet(headerToForward []string) string {
	var location string
	for i, header := range headerToForward {
		location += fmt.Sprintf("auth_request_set $value_%d $upstream_http_%s; ", i, strings.ReplaceAll(header, "-", "_"))
		location += fmt.Sprintf("proxy_set_header %s $value_%d;\n", header, i)
	}

	return location
}

func wrapHubSnippet(s string) string {
	if s == "" {
		return ""
	}

	return fmt.Sprintf("%s\n%s\n%s", hubSnippetTokenStart, strings.TrimSpace(s), hubSnippetTokenEnd)
}

func mergeSnippets(snippets nginxSnippets, anno map[string]string) nginxSnippets {
	return nginxSnippets{
		AuthURL: snippets.AuthURL,
		// AuthSignin:           snippets.AuthSignin,
		// AuthSnippet:          mergeSnippet(anno["nginx.ingress.kubernetes.io/auth-snippet"], snippets.AuthSnippet),
		ConfigurationSnippet: mergeSnippet(anno["nginx.ingress.kubernetes.io/configuration-snippet"], snippets.ConfigurationSnippet),
		ServerSnippet:        mergeSnippet(anno["nginx.ingress.kubernetes.io/server-snippet"], snippets.ServerSnippet),
	}
}

var re = regexp.MustCompile(fmt.Sprintf(`(?ms)^(.*)(%s.*%s)(.*)$`, hubSnippetTokenStart, hubSnippetTokenEnd))

func mergeSnippet(oldSnippet, hubSnippet string) string {
	matches := re.FindStringSubmatch(oldSnippet)
	if len(matches) == 4 {
		return matches[1] + hubSnippet + matches[3]
	}

	if oldSnippet != "" && hubSnippet != "" {
		return oldSnippet + "\n" + hubSnippet
	}

	return oldSnippet + hubSnippet
}
