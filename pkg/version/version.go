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
	ua := fmt.Sprintf("hub-agent-kubernetes/%s (%s; %s; %s)", Version(), commit, runtime.GOOS, runtime.GOARCH)
	req.Header.Set("User-Agent", strings.TrimSpace(ua))
}

// addHeaderTransport allows to add header to http request.
type addHeaderTransport struct {
	T http.RoundTripper
}

// RoundTrip implements RoundTripper interface.
func (adt *addHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("Traefik-Hub-Agent-Version", version)
	req.Header.Add("Traefik-Hub-Agent-Platform", "kubernetes")

	return adt.T.RoundTrip(req)
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
	client clusterService
}

// NewChecker returns a new Checker.
func NewChecker(client clusterService) *Checker {
	return &Checker{client: client}
}

// CheckNewVersion checks if a new version is available.
func (c *Checker) CheckNewVersion(ctx context.Context) error {
	if version == "dev" {
		return nil
	}

	currentVersion, err := goversion.NewVersion(version)
	if err != nil {
		return fmt.Errorf("new version: %w", err)
	}

	updateURL, err := url.Parse("https://update.traefik.io/")
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}

	client := github.NewClient(&http.Client{Transport: &addHeaderTransport{T: http.DefaultTransport}})
	client.UserAgent = fmt.Sprintf("hub-agent-kubernetes/%s (%s; %s; %s)", version, commit, runtime.GOOS, runtime.GOARCH)
	client.BaseURL = updateURL

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	releases, resp, err := client.Repositories.ListReleases(ctx, "traefik", "hub-agent-kubernetes", nil)
	if err != nil {
		return fmt.Errorf("list releases: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		all, _ := io.ReadAll(resp.Body)

		return fmt.Errorf("list releases: %s", string(all))
	}

	for _, release := range releases {
		releaseVersion, versionErr := goversion.NewVersion(*release.TagName)
		if versionErr != nil {
			return fmt.Errorf("new version: %w", versionErr)
		}

		if currentVersion.Prerelease() == "" && releaseVersion.Prerelease() != "" {
			continue
		}

		if releaseVersion.GreaterThan(currentVersion) {
			versionErr := c.client.SetVersionStatus(ctx, Status{
				UpToDate:       false,
				CurrentVersion: version,
				LastVersion:    *release.TagName,
			})
			if versionErr != nil {
				return fmt.Errorf("set version status: %w", versionErr)
			}

			return fmt.Errorf("a new release has been found: %s. Please consider updating", releaseVersion.String())
		}
	}

	err = c.client.SetVersionStatus(ctx, Status{
		UpToDate:       true,
		CurrentVersion: version,
		LastVersion:    version,
	})
	if err != nil {
		return fmt.Errorf("set version status: %w", err)
	}

	return nil
}
