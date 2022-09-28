/*
Copyright (C) 2022 Traefik Labs

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package version

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/go-github/v47/github"
	goversion "github.com/hashicorp/go-version"
	"github.com/rs/zerolog/log"
)

// These variables are set when compiling the project.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

var versionTemplate = `Version:      {{.Version}}
Commit:       {{ .Commit }}
Go version:   {{.GoVersion}}
Built:        {{.BuildTime}}
OS/Arch:      {{.Os}}/{{.Arch}}
`

// Print prints the full version information on the given writer.
func Print(w io.Writer) error {
	tmpl, err := template.New("").Parse(versionTemplate)
	if err != nil {
		return err
	}

	v := struct {
		Version   string
		Commit    string
		BuildTime string
		GoVersion string
		Os        string
		Arch      string
	}{
		Version:   version,
		Commit:    commit,
		BuildTime: date,
		GoVersion: runtime.Version(),
		Os:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}

	return tmpl.Execute(w, v)
}

// String returns a quick summary of version information.
func String() string {
	return fmt.Sprintf("%s, build %s on %s", version, commit, date)
}

// Version returns the agent version.
func Version() string {
	return version
}

// Log logs the full version information.
func Log() {
	log.Info().
		Str("version", version).
		Str("module", moduleName()).
		Str("commit", commit).
		Str("built", date).
		Str("go_version", runtime.Version()).
		Str("os", runtime.GOOS).
		Str("arch", runtime.GOARCH).
		Send()
}

func moduleName() string {
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		return buildInfo.Main.Path
	}
	return ""
}

// SetUserAgent sets the user-agent on an HTTP request.
func SetUserAgent(req *http.Request) {
	req.Header.Set("User-Agent", strings.TrimSpace(userAgent()))
}

func userAgent() string {
	return fmt.Sprintf("hub-agent-kubernetes/%s (%s; %s; %s)", version, commit, runtime.GOOS, runtime.GOARCH)
}

// addHeaderTransport allows to add header to http request.
type addHeaderTransport struct {
	http.RoundTripper
}

// RoundTrip add headers to http request.
func (adt *addHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("Traefik-Hub-Agent-Version", version)
	req.Header.Add("Traefik-Hub-Agent-Platform", "kubernetes")

	return adt.RoundTripper.RoundTrip(req)
}

// Status holds agent version data.
type Status struct {
	UpToDate       bool
	CurrentVersion string
	LastVersion    string
}

type clusterService interface {
	SetVersionStatus(ctx context.Context, state Status) error
}

// Checker is able to check the agent version.
type Checker struct {
	cluster clusterService
	client  *github.Client
}

// NewChecker returns a new Checker.
func NewChecker(cluster clusterService) (*Checker, error) {
	updateURL, err := url.Parse("https://update.traefik.io/")
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	githubClient := github.NewClient(&http.Client{Transport: &addHeaderTransport{http.DefaultTransport}})
	githubClient.UserAgent = userAgent()
	githubClient.BaseURL = updateURL

	return &Checker{cluster: cluster, client: githubClient}, nil
}

// Start starts the check of the agent version.
func (c Checker) Start(ctx context.Context) error {
	tick := time.NewTicker(24 * time.Hour)
	defer tick.Stop()

	time.Sleep(10 * time.Second)

	if err := c.check(ctx); err != nil {
		log.Warn().Err(err).Msg("check new version ")
	}

	for {
		select {
		case <-tick.C:
			if err := c.check(ctx); err != nil {
				log.Warn().Err(err).Msg("check new version ")
			}

		case <-ctx.Done():
			return nil
		}
	}
}

// check Checks if a new version is available.
func (c Checker) check(ctx context.Context) error {
	if version == "dev" {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	tags, resp, err := c.client.Repositories.ListTags(ctx, "traefik", "hub-agent-kubernetes", nil)
	if err != nil {
		return fmt.Errorf("list tags: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		all, _ := io.ReadAll(resp.Body)

		return fmt.Errorf("list tags: %s", string(all))
	}

	lastVersion, err := goversion.NewSemver(tags[0].GetName())
	if err != nil {
		return fmt.Errorf("parse version: %w", err)
	}

	currentVersion, err := goversion.NewSemver(version)
	// not a valid tag.
	if err != nil {
		versionErr := c.cluster.SetVersionStatus(ctx, Status{
			UpToDate:       false,
			CurrentVersion: version,
			LastVersion:    lastVersion.Original(),
		})
		if versionErr != nil {
			return fmt.Errorf("set version status: %w", versionErr)
		}

		return fmt.Errorf("you are using %s version of the agent, please consider upgrading to %s", version, lastVersion.Original())
	}

	// upToDate version.
	if lastVersion.GreaterThan(currentVersion) {
		versionErr := c.cluster.SetVersionStatus(ctx, Status{
			UpToDate:       false,
			CurrentVersion: version,
			LastVersion:    lastVersion.Original(),
		})
		if versionErr != nil {
			return fmt.Errorf("set version status: %w", versionErr)
		}

		return fmt.Errorf("you are using %s version of the agent, please consider upgrading to %s", version, lastVersion.Original())
	}

	err = c.cluster.SetVersionStatus(ctx, Status{
		UpToDate:       true,
		CurrentVersion: version,
		LastVersion:    version,
	})
	if err != nil {
		return fmt.Errorf("set version status: %w", err)
	}

	return nil
}
