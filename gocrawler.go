package main

import (
	"fmt"
	"regexp"
)

// meta data
var VERSION = "0.1.2"
var STATUS_LINE_NAME = fmt.Sprintf("[gocrawler/v%s]", VERSION)

// option structure
type Options struct {
	Robots            bool
	Sitemap           bool
	WayBack           bool
	IgnoreInvalidSSL  bool
	Thread            int
	Timeout           int
	Delay             int
	Depth             int
	MaxRegexResult    int
	URL               string
	Proxy             string
	RegexString       string
	Regex             *regexp.Regexp
	URLExclude        string
	URLExcludeRegex   *regexp.Regexp
	StatusCodeExclude string
	StatusCodeRegex   *regexp.Regexp
	InScopeExclude    string
	Scheme            string
	Headers           string
	Query             string
	Keys              []string
	InScopeDomains    []string
}

// output result structure
type Results struct {
	Pages        string
	PageByURL    map[string]string
	URLs         map[string]bool
	OutScopeURLs map[string]bool
	QueryURLs    map[string]bool
	CSS          map[string]bool
	Scripts      map[string]bool
	CDNs         map[string]bool
	Medias       map[string]bool
	Emails       map[string]bool
	Phones       map[string]bool
	Networks     map[string]bool
	Comments     map[string]bool
	HostNames    []string
	RegMaches    map[string][]string
}
