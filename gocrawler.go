package main

import (
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/jroimartin/gocui"
)

// Metadata
var VERSION = "0.1.2"
var STATUS_LINE_NAME = fmt.Sprintf("[evine/v%s]", VERSION)

// Options structure
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

// Output result structure
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

// Program definitions
type def struct {
	currentPage      string
	currentPageIndex int
	Gui              *gocui.Gui
}

// CUI View Attributes
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
