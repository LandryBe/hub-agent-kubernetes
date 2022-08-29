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

	authURL              = "nginx.ingress.kubernetes.io/auth-url"
	authSignin           = "nginx.ingress.kubernetes.io/auth-signin"
	authSnippet          = "nginx.ingress.kubernetes.io/auth-snippet"
	configurationSnippet = "nginx.ingress.kubernetes.io/configuration-snippet"
	serverSnippet        = "nginx.ingress.kubernetes.io/server-snippet"
)

func genNginxAnnotations(polName string, polCfg *acp.Config, agentAddr string) (map[string]string, error) {
	headerToFwd, err := headerToForward(polCfg)
	if err != nil {
		return nil, fmt.Errorf("get header to forward: %w", err)
	}

	locSnip := generateLocationSnippet(headerToFwd)

	if polCfg.OIDC == nil {
		return map[string]string{
			authURL:              fmt.Sprintf("%s/%s", agentAddr, polName),
			configurationSnippet: wrapHubSnippet(locSnip),
		}, nil
	}

	redirectPath, err := redirectPath(polCfg)
	if err != nil {
		return nil, err
	}

	headers := `
proxy_set_header From nginx;
proxy_set_header X-Forwarded-Uri $request_uri;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Method $request_method;`
	authServerURL := fmt.Sprintf("%s/%s", agentAddr, polName)

	return map[string]string{
		authURL:              authServerURL,
		authSignin:           "$url_redirect",
		authSnippet:          wrapHubSnippet(headers),
		configurationSnippet: wrapHubSnippet(locSnip + " auth_request_set $url_redirect $upstream_http_url_redirect;"),
		serverSnippet:        wrapHubSnippet(fmt.Sprintf("location %s { proxy_pass %s; %s}", redirectPath, authServerURL, headers)),
	}, nil
}

func redirectPath(polCfg *acp.Config) (string, error) {
	u, err := url.Parse(polCfg.OIDC.RedirectURL)
	if err != nil {
		return "", fmt.Errorf("parse redirect url: %w", err)
	}

	redirectPath := u.Path
	if redirectPath == "" {
		redirectPath = "/callback"
	}

	if redirectPath[0] != '/' {
		redirectPath = "/" + redirectPath
	}

	return redirectPath, nil
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

func mergeSnippets(nginxAnno, anno map[string]string) map[string]string {
	nginxAnno[authSnippet] = mergeSnippet(anno[authSnippet], nginxAnno[authSnippet])
	nginxAnno[configurationSnippet] = mergeSnippet(anno[configurationSnippet], nginxAnno[configurationSnippet])
	nginxAnno[serverSnippet] = mergeSnippet(anno[serverSnippet], nginxAnno[serverSnippet])

	return nginxAnno
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
