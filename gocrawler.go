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

// func for status code exclude option
func statusCodeExcluding(code int) bool {
	reg := regexp.MustCompile(OPTIONS.StatusCodeExclude)
	if reg.MatchString(strconv.Itoa(code)) {
		return true
	}
	return false
}

// send the request and gives the source, status code, erros
func request(uri string) (string, int, error) {
	client := &http.Client{
		Timeout: time.Duration(OPTIONS.Timeout) * time.Second}
	Httptransport := &http.Transport{}
	if OPTIONS.Proxy != "" {
		proxy, er := url.Parse(OPTIONS.Proxy)
		if er != nil {
			return "", 0, er
		}
		Httptransport.Proxy = http.ProxyURL(proxy)
	}
	if OPTIONS.IgnoreInvalidSSL == true {
		Httptransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client = &http.Client{Transport: Httptransport}
	req, er := http.NewRequest("GET", trim(uri), nil)
	if er != nil {
		return "", 0, er
	}
	headers := strings.Split(trim(VIEWS_OBJ["HEADERS"].Buffer()), "\n")
	for _, v := range headers {
		kv := strings.Split(v, ": ")
		kv[0] = strings.Replace(kv[0], " ", "", -1)
		req.Header.Set(kv[0], kv[1])
	}
	resp, er := client.Do(req)
	if er != nil {
		return "", 0, er
	}
	defer resp.Body.Close()
	Body, er := ioutil.ReadAll(resp.Body)
	if er != nil {
		return "", 0, er
	}
	return string(Body), resp.StatusCode, er
}

// func for sanitizing the url and return a list of urls
func crawlWayBackURLs() []string {
	// Fetch waybackurls need almost 15s timeout
	timeout := OPTIONS.Timeout
	OPTIONS.Timeout = 15
	text, _, ok := request(fmt.Sprintf("%s://web.archive.org/cdx/search/cdx?url=%s/*&output=json&collapse=urlkey", OPTIONS.Scheme, PROJECT_NAME))
	OPTIONS.Timeout = timeout
	if ok != nil {
		return []string{}
	}
	var wrapper [][]string
	ok = json.Unmarshal([]byte(text), &wrapper)
	if ok != nil {
		return []string{}
	}
	var wayURLs []string
	var code int
	for _, urls := range wrapper[1:] {
		code, _ = strconv.Atoi(urls[4])
		// Exclude the urls with codeExclude and urlExclude
		if statusCodeExcluding(code) && urlExcluding(urls[2]) {
			parse, ok := url.Parse(urls[2])
			if ok != nil {
				continue
			}
			parse.Host = regexp.MustCompile(`:[\d]+`).ReplaceAllString(parse.Host, "")
			marshal, ok := parse.MarshalBinary()
			if ok != nil {
				continue
			}
			url := fmt.Sprintf("%s", marshal)
			wayURLs = append(wayURLs, strings.ReplaceAll(url, `\/\/`, `//`))
		}
	}
	return wayURLs
}

// crawl the robots.txt in the url
func crawlRobots() []string {
	text, statusCode, ok := request(fmt.Sprintf("%s://%s/robots.txt", OPTIONS.Scheme, PROJECT_NAME))

	if ok != nil {
		return []string{}
	}
	if statusCode == 200 {
		var reg *regexp.Regexp
		makers := []string{}
		// It finds all of URLs without any restrict
		for _, obj := range [3]string{`Disallow: (.*)?`, `Allow: (.*)?`, `Sitemap: (.*)?`} {
			reg = regexp.MustCompile(obj)
			for _, link := range [][]string(reg.FindAllStringSubmatch(text, -1)) {
				makers = append(makers, string(link[1]))
			}
		}
		return makers
	}
	return []string{}
}

// crawling the sitemap.xml 
func crawlSitemap() []string {
	text, statusCode, ok := request(fmt.Sprintf("%s://%s/sitemap.xml", OPTIONS.Scheme, PROJECT_NAME))
	if ok != nil {
		return []string{}
	}
	reg := regexp.MustCompile(`<loc>(.*?)</loc>`)
	if statusCode == 200 {
		founds := reg.FindAllStringSubmatch(text, -1)
		out := []string{}
		for _, v := range founds {
			out = append(out, v[1])
		}
		return out
	}
	return []string{}
}

// find social networks with regex
func checkPostfix(file string, uri string) bool {
	file = strings.ToLower(file)
	uri = strings.ToLower(uri)
	reg := regexp.MustCompile(`\.` + file + `[^\w]`)
	reg2 := regexp.MustCompile(`\.` + file + `[^\w]?$`)

	if reg.MatchString(uri) || reg2.MatchString(uri) || strings.HasSuffix(uri, "."+file) {
		return true
	}
	return false
}

// set view properties
func settingViews() {
	VIEWS_ATTRS = map[string]viewAttrs{
		"URL": {
			editor:   &singleLineEditor{gocui.DefaultEditor},
			editable: true,
			frame:    true,
			text:     OPTIONS.URL,
			title:    "URL",
			wrap:     false,
			x0:       func(x int) int { return x - x },
			y0:       func(y int) int { return 0 },
			x1:       func(x int) int { return x - 1 },
			y1:       func(y int) int { return 2 },
		},
		"OPTIONS": {
			editor:   gocui.DefaultEditor,
			editable: true,
			frame:    true,
			text:     optionsCode(),
			title:    "Options",
			wrap:     true,
			x0:       func(x int) int { return 0 },
			y0:       func(y int) int { return 2 },
			x1:       func(x int) int { return x / 2 },
			y1:       func(y int) int { return (y / 2) / 2 },
		},
		"HEADERS": {
			editor:   gocui.DefaultEditor,
			editable: true,
			frame:    true,
			text:     OPTIONS.Headers,
			title:    "HTTP Headers",
			wrap:     true,
			x0:       func(x int) int { return x / 2 },
			y0:       func(y int) int { return (y - y) + 2 },
			x1:       func(x int) int { return x - 1 },
			y1:       func(y int) int { return (y / 2) / 2 },
		},
		"QUERY": {
			editor:   &singleLineEditor{gocui.DefaultEditor},
			editable: true,
			frame:    true,
			text:     OPTIONS.Query,
			title:    "Query",
			wrap:     false,
			x0:       func(x int) int { return 0 },
			y0:       func(y int) int { return (y / 2) / 2 },
			x1:       func(x int) int { return x / 2 },
			y1:       func(y int) int { return ((y / 2) / 2) + 2 },
		},
		"REGEX": {
			editor:   &singleLineEditor{gocui.DefaultEditor},
			editable: true,
			frame:    true,
			text:     OPTIONS.RegexString,
			title:    "Regex",
			wrap:     false,
			x0:       func(x int) int { return x / 2 },
			y0:       func(y int) int { return (y / 2) / 2 },
			x1:       func(x int) int { return x - 1 },
			y1:       func(y int) int { return ((y / 2) / 2) + 2 },
		},
		"RESPONSE": {
			editor:   &responseEditor{gocui.DefaultEditor},
			editable: true,
			frame:    true,
			title:    "Response",
			wrap:     true,
			x0:       func(x int) int { return 0 },
			y0:       func(y int) int { return (y/2)/2 + 2 },
			x1:       func(x int) int { return x - 1 },
			y1:       func(y int) int { return y - 4 },
		},
		"STATUS_LINE": {
			editor:   nil,
			editable: false,
			frame:    true,
			wrap:     true,
			text:     STATUS_LINE_NAME,
			x0:       func(x int) int { return 0 },
			y0:       func(y int) int { return y - 4 },
			x1:       func(x int) int { return x - 1 },
			y1:       func(y int) int { return y - 2 },
		},
		"SEARCH": {
			editor:   nil,
			editable: false,
			text:     "search>",
			frame:    false,
			wrap:     false,
			x0:       func(x int) int { return 0 },
			y0:       func(y int) int { return y - 2 },
			x1:       func(x int) int { return 8 },
			y1:       func(y int) int { return y },
		},
		"SEARCH_PROMPT": {
			editor:   &singleLineEditor{&searchEditor{gocui.DefaultEditor}},
			editable: true,
			frame:    false,
			wrap:     false,
			x0:       func(x int) int { return 8 },
			y0:       func(y int) int { return y - 2 },
			x1:       func(x int) int { return x - 1 },
			y1:       func(y int) int { return y },
		},
		"ERROR": {
			editor:   nil,
			editable: false,
			text:     "Terminal is too small",
			title:    "Error",
			frame:    true,
			wrap:     false,
			x0:       func(x int) int { return 0 },
			y0:       func(y int) int { return 0 },
			x1:       func(x int) int { return x - 1 },
			y1:       func(y int) int { return y - 1 },
		},
		"SAVE": {
			editor:   &singleLineEditor{gocui.DefaultEditor},
			editable: true,
			text:     "Terminal is too small",
			title:    "Filename (Enter to submit, Ctrl+q to close)",
			frame:    true,
			wrap:     false,
			x0:       func(x int) int { return (x / 2) / 2 },
			y0:       func(y int) int { return y/2 - 1 },
			x1:       func(x int) int { return x - ((x / 2) / 2) },
			y1:       func(y int) int { return y/2 + 1 },
		},
		"SAVE_RESULT": {
			editor:   nil,
			editable: false,
			title:    "Result save(Ctrl+q to close)",
			frame:    true,
			wrap:     false,
			x0:       func(x int) int { return (x / 2) / 2 },
			y0:       func(y int) int { return (y / 2) + 1 },
			x1:       func(x int) int { return x - ((x / 2) / 2) },
			y1:       func(y int) int { return (y / 2) + 3 },
		},
		"LOADER": {
			editor:   nil,
			editable: false,
			text:     "Loading...",
			frame:    true,
			wrap:     false,
			x0:       func(x int) int { return (x / 2) - 5 },
			y0:       func(y int) int { return (y / 2) + 1 },
			x1:       func(x int) int { return ((x / 2) + 6) },
			y1:       func(y int) int { return (y / 2) + 3 },
		},
	}
}

// put the msg to the response view
func putting(v *gocui.View, msg string) {
	PROG.Gui.Update(func(_ *gocui.Gui) error {
		fmt.Fprintln(v, msg)
		return nil
	})
}
