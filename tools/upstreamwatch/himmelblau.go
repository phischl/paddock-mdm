package main

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

// HimmelblauIndex is the directory listing of the stable Himmelblau packages.
const HimmelblauIndex = "https://packages.himmelblau-idm.org/stable/"

var hrefRE = regexp.MustCompile(`href="([^"]+)"`)

var releaseDirRE = regexp.MustCompile(`^\d+\.\d+\.\d+/$`)

// HimmelblauLatest returns the highest x.y.z/ entry of the index page.
func HimmelblauLatest(html string) (string, error) {
	var versions []string
	for _, m := range hrefRE.FindAllStringSubmatch(html, -1) {
		if releaseDirRE.MatchString(m[1]) {
			versions = append(versions, strings.TrimSuffix(m[1], "/"))
		}
	}
	latest := Latest("0.0.0", versions)
	if latest == "" {
		return "", errors.New("himmelblau index lists no x.y.z/ release")
	}
	return latest, nil
}

// FetchHimmelblau reads the index page and returns the highest release.
func FetchHimmelblau(ctx context.Context, c *http.Client, index string) (string, error) {
	b, err := getBody(ctx, c, index, nil)
	if err != nil {
		return "", err
	}
	return HimmelblauLatest(string(b))
}
