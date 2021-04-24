package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/jroimartin/gocui"
)

// meta datas
var VERSION = "0.1.2"
var STATUS_LINE_NAME = fmt.Sprintf("[evine/v%s]", VERSION)

// options structure
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

// program definitions
type def struct {
	currentPage      string
	currentPageIndex int
	Gui              *gocui.Gui
}

// CUI view attributes
type viewAttrs struct {
	editor   gocui.Editor
	editable bool
	frame    bool
	text     string
	title    string
	wrap     bool
	x0       func(int) int
	y0       func(int) int
	x1       func(int) int
	y1       func(int) int
}

// Search prompt editor struct type
type searchEditor struct {
	editor gocui.Editor
}

// URL editor struct type
type singleLineEditor struct {
	editor gocui.Editor
}

// RESPONSE editor struct type
type responseEditor struct {
	editor gocui.Editor
}

var (
	// Initial OPTIONS
	OPTIONS = &Options{}
	// To identify media postfixes
	MEDIA_POSTFIX = []string{"aa", "aac", "aif", "aiff", "amr", "amv", "amz", "ape", "asc", "asf", "au", "bash", "bat", "bmp", "c",
		"cfa", "chm", "cpp", "cs", "csv", "doc", "docx", "dmg", "f4a", "f4b", "f4p", "f4v", "flac", "flv", "gif", "gif", "gifv",
		"go", "gz", "ico", "java", "jfif", "jpeg", "jpg", "m2v", "m4a", "m4p", "m4v", "md", "mkv", "mng", "mov",
		"mp2", "mp3", "mp4", "mpeg", "mpg", "mpv", "msi", "pdf", "pl", "png", "ppt", "pptx", "py", "rar", "rm", "roq",
		"svg", "svi", "tar.gz", "tiff", "vmo", "vob", "w64", "wav", "webm", "wma", "wmv", "woff2", "wrk",
		"wvavi", "xlsx", "xz", "yaml", "yml", "zip", "7z", "tgz", "exe", "psd"}
	// Scheme://hostname.tld
	BASEURL = ""
	// Project Name: Hostname.tld
	PROJECT_NAME = ""
	VIEWS        = []string{"URL", "OPTIONS", "HEADERS", "QUERY", "REGEX", "RESPONSE", "SEARCH_PROMPT"}
	ALL_VIEWS    = []string{"URL", "OPTIONS", "HEADERS", "QUERY", "REGEX", "RESPONSE", "SEARCH", "STATUS_LINE", "SEARCH_PROMPT"}
	// Pre-define keys
	ALL_KEYS    = []string{"email", "url", "query_urls", "all_urls", "phone", "media", "css", "script", "cdn", "comment", "dns", "network", "all"}
	MIN_X       = 60
	MIN_Y       = 20
	VIEWS_OBJ   map[string]*gocui.View
	VIEWS_ATTRS = map[string]viewAttrs{}
	PROG        def
	DEPTH       = 1
	TOKENS      chan struct{}
	RESULTS     *Results
	START_TIME  time.Time
	MUTEX       = &sync.Mutex{}
)

// Find comments
func findComments() {
	reg := regexp.MustCompile(`<!--.*?-->`)
	for _, v := range reg.FindAllString(RESULTS.Pages, -1) {
		if !RESULTS.Comments[v] {
			RESULTS.Comments[v] = true
		}
	}
}

// Find emails
func findEmails() {
	reg := regexp.MustCompile(`[A-z0-9.\-_]+@[A-z0-9\-\.]{0,255}?` + PROJECT_NAME + `(?:[A-z]+)?`)
	founds := reg.FindAllString(RESULTS.Pages, -1)
	reg = regexp.MustCompile(`[A-z0-9.\-_]+@[A-z0-9\-.]+\.[A-z]{1,10}`)
	for _, v := range reg.FindAllString(RESULTS.Pages, -1) {
		if strings.Contains(strings.Split(v, "@")[1], ".") {
			founds = append(founds, strings.ToLower(v))
		}
	}
	for _, v := range founds {
		v = strings.ToLower(v)
		if !RESULTS.Emails[v] && toBool(v) {
			RESULTS.Emails[v] = true
		}
	}
}

// find project DNS names
func findHostnames() {
	reg := regexp.MustCompile(`[A-z0-9\.\-%]+\.` + PROJECT_NAME)
	for _, v := range reg.FindAllString(RESULTS.Pages, -1) {
		uniq(&RESULTS.HostNames, v)
	}
}

// Find social media 
func findNetworks() {
	netexp := `(instagram\.com\/[A-z_0-9.\-]{1,30})|(facebook\.com\/[A-z_0-9\-]{2,50})|(fb\.com\/[A-z_0-9\-]{2,50})|(twitter\.com\/[A-z_0-9\-.]{2,40})|(github\.com\/[A-z0-9_-]{1,39})|([A-z0-9_-]{1,39}\.github.(io|com))|(telegram\.me/[A-z_0-9]{5,32})(youtube\.com\/user\/[A-z_0-9\-\.]{2,100})|(linkedin\.com\/company\/[A-z_0-9\.\-]{3,50})|(linkedin\.com\/in\/[A-z_0-9\.\-]{3,50})|(\.?(plus\.google\.com/[A-z0-9_\-.+]{3,255}))|([A-z0-9\-]+\.wordpress\.com)|(reddit\.com/user/[A-z0-9_\-]{3,20})|([A-z0-9\-]{3,32}\.tumblr\.com)|([A-z0-9\-]{3,50}\.blogspot\.com)`

	reg := regexp.MustCompile(netexp)
	found := reg.FindAllString(RESULTS.Pages, -1)
	for _, i := range found {
		if !RESULTS.Networks[i] {
			RESULTS.Networks[i] = true
		}
	}
}


// it will true if the url matched with the urlexcldue option
func urlExcluding(uri string) bool {
	if OPTIONS.URLExcludeRegex.MatchString(uri) {
		return true
	}
	return false
}