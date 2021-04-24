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
