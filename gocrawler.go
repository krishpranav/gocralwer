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

// push msg to response view
func pushing(msg string) {
	fmt.Fprintln(VIEWS_OBJ["RESPONSE"], msg)
}

// shows the defference of the start time to now
func sinceTime() float64 {
	return time.Since(START_TIME).Seconds()
}

// refresh the status line with new value
func refStatusLine(msg string) {
	VIEWS_OBJ["STATUS_LINE"].Clear()
	putting(VIEWS_OBJ["STATUS_LINE"], STATUS_LINE_NAME+" "+msg)
}

// show the loading pop up view
func loading() error {
	X, Y := PROG.Gui.Size()
	attrs := VIEWS_ATTRS["LOADER"]
	if v, err := PROG.Gui.SetView("LOADER", attrs.x0(X), attrs.y0(Y), attrs.x1(X), attrs.y1(Y)); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		setViewAttrs(v, attrs)
	}
	return nil
}

// function for parses the command line flags provided by a user
func parseOptions() {
	flag.StringVar(&OPTIONS.URL, "url", "", "URL to crawl for")
	flag.IntVar(&OPTIONS.Thread, "thread", 5, "The number of concurrent goroutines for resolving")
	flag.IntVar(&OPTIONS.Delay, "delay", 0, "Sleep between each request(Millisecond)")
	flag.IntVar(&OPTIONS.Timeout, "timeout", 10, "Seconds to wait before timing out")
	flag.IntVar(&OPTIONS.MaxRegexResult, "max-regex", 1000, "Max result of regex search for regex field")
	flag.BoolVar(&OPTIONS.Robots, "robots", false, "Scrape robots.txt for URLs and using them as seeds")
	flag.BoolVar(&OPTIONS.Sitemap, "sitemap", false, "Scrape sitemap.xml for URLs and using them as seeds")
	flag.BoolVar(&OPTIONS.WayBack, "wayback", false, "Scrape WayBackURLs(web.archive.org) for URLs and using them as seeds")
	flag.BoolVar(&OPTIONS.IgnoreInvalidSSL, "Ignore-SSL", false, "Ignore invalid SSL")
	flag.StringVar(&OPTIONS.Query, "query", "", `Query expression(It could be a file extension(pdf), a key query(url,script,css,..) or a jquery selector($("a[class='hdr']).attr('hdr')")))`)
	flag.StringVar(&OPTIONS.Proxy, "proxy", "", "Proxy by scheme://ip:port")
	flag.StringVar(&OPTIONS.Headers, "header", "", "HTTP Header for each request(It should to separated fields by \\n). e.g KEY: VALUE\\nKEY1: VALUE1")
	flag.StringVar(&OPTIONS.RegexString, "regex", "", "Search the Regular Expression on the pages")
	flag.StringVar(&OPTIONS.Scheme, "scheme", "https", "Set the scheme for the requests")
	flag.IntVar(&OPTIONS.Depth, "depth", 1, "Scraper depth search level")
	flag.StringVar(&OPTIONS.URLExclude, "url-exclude", ".*", "Exclude URLs matching with this regex")
	flag.StringVar(&OPTIONS.StatusCodeExclude, "code-exclude", ".*", "Exclude HTTP status code with these codes. Separate whit '|'")
	flag.StringVar(&OPTIONS.InScopeExclude, "domain-exclude", "", "Exclude in-scope domains to crawl. Separate with comma | default=root domain")
	flag.Parse()
	if OPTIONS.URL != "" {
		OPTIONS.URL = urlSanitize(OPTIONS.URL)
	} else {
		OPTIONS.URL = "https://"
	}
	if !toBool(OPTIONS.Headers) {
		OPTIONS.Headers = `User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0`
	}
}

// will show the options to view as text
func optionsCode() string {
	B2S := func(b bool) string {
		if b == true {
			return "true"
		}
		return "false"
	}
	return fmt.Sprintf("thread,depth,delay,timeout,maxRegexResult=%d,%d,%d,%d,%d\nrobots,sitemap,wayback=%s,%s,%s\nurlExclude=%s\ncodeExclude=%s\ndomainExclude=%s\nproxy=%s\nIgnoreInvalidSSL=%s",
		OPTIONS.Thread, OPTIONS.Depth, OPTIONS.Delay, OPTIONS.Timeout, OPTIONS.MaxRegexResult,
		B2S(OPTIONS.Robots), B2S(OPTIONS.Sitemap), B2S(OPTIONS.WayBack), OPTIONS.URLExclude,
		OPTIONS.StatusCodeExclude, OPTIONS.InScopeExclude, OPTIONS.Proxy, B2S(OPTIONS.IgnoreInvalidSSL))
}

// will show the option from the option view and set them
func prepareOptions() string {
	S2B := func(v string) bool {
		if v == "true" {
			return true
		}
		return false
	}
	code := trim(VIEWS_OBJ["OPTIONS"].Buffer())
	if !toBool(code) {
		return "Options are incomplete. Press Ctrl+R to rewrite options."
	}
	for k, line := range strings.Split(code, "\n") {
		split := strings.Split(line, "=")
		values := strings.Join(split[1:], "=")
		splited := strings.Split(values, ",")
		// If count of the variables doesn't match with values
		if len(splited) != len(strings.Split(split[0], ",")) {
			return "Options are incomplete: All int and bool options must be set. Press Ctrl+R to rewrite options."
		}
		switch k {
		// Set the int variables
		case 0:
			var k int
			var v *int
			for k, v = range []*int{&OPTIONS.Thread, &OPTIONS.Depth, &OPTIONS.Delay, &OPTIONS.Timeout, &OPTIONS.MaxRegexResult} {
				if i, err := strconv.Atoi(splited[k]); err == nil {
					*v = i
				} else {
					return fmt.Sprintf("Invalid value for type int: %s.", splited[k])
				}
			}
		// Set the boolean variables
		case 1:
			OPTIONS.Robots, OPTIONS.Sitemap, OPTIONS.WayBack = S2B(splited[0]), S2B(splited[1]), S2B(splited[2])
		// Set the urlExclude,.. variables
		case 2:
			OPTIONS.URLExclude = values
		case 3:
			OPTIONS.StatusCodeExclude = values
		case 4:
			OPTIONS.InScopeDomains = strings.Split(values, ",")
		case 5:
			OPTIONS.Proxy = values
		case 6:
			OPTIONS.IgnoreInvalidSSL = S2B(values)
		}
	}
	// Prepare the URLs channel for crawl
	TOKENS = make(chan struct{}, OPTIONS.Thread)
	// Init Headers
	OPTIONS.Headers = trim(VIEWS_OBJ["HEADERS"].Buffer())
	prepareQuery()
	return ""
}

// will split the keys as slice and write it as OPTIONS.Keys
func prepareQuery() {
	q := trim(VIEWS_OBJ["QUERY"].Buffer())
	if !strings.HasPrefix(q, "$") {
		OPTIONS.Keys = strings.Split(q, ",")
	} else {
		OPTIONS.Query = q
	}
}

// return false if arg is blank and true if it isn't
// supported types: int, string, bool, []int, []string, []bool
func toBool(arg interface{}) bool {
	switch arg.(type) {
	case int:
		return arg != 0
	case string:
		return arg != ""
	case bool:
		return arg == true
	case rune:
		return true
	default:
		tostr, ok := arg.([]string)
		if ok {
			return toBool(len(tostr))
		}
		toint, ok := arg.([]int)
		if ok {
			return toBool(len(toint))
		}
		toflag, ok := arg.([]bool)
		if ok {
			return toBool(len(toflag))
		}
	}
	return false
}

// print the slices
func slicePrint(head string, s []string) {
	pushing(head)
	for v := range s {
		pushing(s[v])
	}
}

// print the maps
func mapPrint(head string, m map[string]bool) {
	pushing(head)
	for k := range m {
		pushing(fmt.Sprintf("    %s", k))
	}
}

// search a key to list and return the true if it is
func sliceSearch(list *[]string, i string) bool {
	for _, v := range *list {
		if v == i {
			return true
		}
	}
	return false
}

// search the regex on the web pages and show the result on the response view
func regexSearch() {
	loading()
	PROG.Gui.Update(func(_ *gocui.Gui) error {
		vrb := VIEWS_OBJ["RESPONSE"]
		vrb.Clear()
		if RESULTS != nil {
			for k, v := range RESULTS.PageByURL {
				founds := OPTIONS.Regex.FindAllString(v, OPTIONS.MaxRegexResult)
				// Print page address and len of results
				pushing(fmt.Sprintf(" > %s | %d", k, len(founds)))
				if founds != nil {
					for _, v := range founds {
						pushing("     > " + v)
					}
				}
			}
		}
		PROG.currentPage = vrb.Buffer()
		PROG.Gui.DeleteView("LOADER")
		return nil
	})
}

// give a query and return the result of query
func parseQuery(query string) ([]string, string) {
	query = strings.TrimSpace(query)
	// Extract the expressions
	syntaxExp := regexp.MustCompile(`^\$\("([^"]+)"\)\.([\w]+)\(("([^"]+)")?\)`).FindAllStringSubmatch(query, 1)
	outputResult := []string{}
	// Check the syntax of query
	if !toBool(len(syntaxExp)) {
		return outputResult, "Query: Invalid syntax"
	}
	query = strings.ReplaceAll(query, syntaxExp[0][0], "")
	exprs := syntaxExp[0][1:]
	// Check the method names
	methods := []string{"html", "text", "attr"}
	method := exprs[1]
	if !sliceSearch(&methods, method) {
		return outputResult, "Query: Invalid method name"
	}
	// Read the document to parse
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(RESULTS.Pages))
	if err != nil {
		return outputResult, fmt.Sprintf("%s", err)
	}
	var def func(*goquery.Selection) (string, error)
	switch method {
	case "text":
		def = func(obj *goquery.Selection) (string, error) {
			return obj.Text(), nil
		}
	case "html":
		def = func(obj *goquery.Selection) (string, error) {
			return obj.Html()
		}
	case "attr":
		def = func(obj *goquery.Selection) (string, error) {
			attr, _ := obj.Attr(exprs[3])
			return attr, nil
		}
	}
	// Run the query
	doc.Find(exprs[0]).Each(func(i int, obj *goquery.Selection) {
		rsp, err := def(obj)
		if err == nil {
			outputResult = append(outputResult, rsp)
		}
	})
	return outputResult, ""
}

// trim the spaces
func trim(s string) string {
	return strings.TrimSpace(s)
}

// if the i is not in the list uniq append i to the slice
func uniq(list *[]string, i string) {
	is := true
	for _, v := range *list {
		if v == i {
			is = false
		}
	}
	if is {
		*list = append(*list, i)
	}
}

// identify the out scope urls
func isOutScope(host string) bool {
	host = strings.ToLower(host)
	host = strings.Replace(host, "www.", ".", 1)
	sh := strings.Split(strings.ToLower(PROJECT_NAME), ".")
	var suffix string
	if len(sh) > 1 {
		suffix = "." + sh[len(sh)-2] + "." + sh[len(sh)-1]
	} else {
		suffix = "." + PROJECT_NAME
	}
	if !strings.HasSuffix(host, suffix) && !sliceSearch(&OPTIONS.InScopeDomains, host) {
		return true
	}
	return false
}

// url joiner
func urjoin(baseurl, uri string) string {
	urlower := strings.ToLower(uri)
	baseurl = strings.ReplaceAll(baseurl, `\/\/`, `//`)
	var pos int
	for _, v := range []string{" ", "", "/", "#", "http://", "https://"} {
		if urlower == v {
			return ""
		}
	}
	// remove the spaces
	pos = strings.Index(uri, " ")
	if pos > -1 {
		uri = uri[:pos]
	}
	// remove the user@.. portion
	pos = strings.Index(uri, "@")
	if pos > -1 {
		uri = uri[:pos]
	}
	// remove the comments
	pos = strings.Index(uri, "#")
	if pos > -1 {
		uri = uri[:pos]
	}
	if !strings.HasSuffix(baseurl, "/") {
		baseurl = baseurl + "/"
	}
	if strings.HasPrefix(uri, "://") {
		return ""
	}
	if strings.HasPrefix(uri, "//") {
		return baseurl + uri
	}
	if strings.HasPrefix(uri, "/") {
		return baseurl + uri[1:]
	}
	base, err := url.Parse(baseurl)
	if err != nil {
		return ""
	}
	final, err := base.Parse(uri)
	if err != nil {
		return ""
	}
	return final.String()
}

// remove url scheme and replace it with default scheme and
// removes last
func setURLUniq(uri string) string {
	uri = regexp.MustCompile(`https?://`).ReplaceAllString(uri, OPTIONS.Scheme+"://")
	// Remove last slash
	uri = regexp.MustCompile(`/$`).ReplaceAllString(uri, "")
	return uri
}

// setting the url scheme
func urlSanitize(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		uri = OPTIONS.Scheme + uri
		u, err = url.Parse(uri)
		if err != nil {
			return ""
		}
	}
	if u.Scheme == "" {
		uri = strings.Replace(uri, "://", "", -1)
		uri = fmt.Sprintf("%s://%s", OPTIONS.Scheme, uri)

	}
	return uri
}

// function for identify the type of url
func urlCategory(urls []string) []string {
	spool := []string{}
	var join string
	var broke int
	// Sometimes the program is broken with runtime error
	// Then we use Mutex to lock the loop to solve the problem
	MUTEX.Lock()
	defer MUTEX.Unlock()
	for _, link := range urls {
		// If the URL is nothing or blank
		if !toBool(link) {
			continue
		}
		// If the URL is a phone, CDN or email
		if addCDN(link) || addPhone(link) || addEmail(link) {
			continue
		}
		join = urjoin(BASEURL, link)
		if !toBool(join) || !strings.Contains(join, "://") || !strings.Contains(join, ".") {
			continue
		}
		// Identify the media files
		broke = 0
		for _, ext := range MEDIA_POSTFIX {
			if x := checkPostfix(ext, join); x {
				if !RESULTS.Medias[join] {
					RESULTS.Medias[join] = true
				}
				broke = 1
				break
			}
		}
		if broke == 1 {
			continue
		}
		// If it is a JavaScript file
		if checkPostfix("js", join) {
			if !RESULTS.Scripts[join] {
				RESULTS.Scripts[join] = true
			}
			continue
		}
		// If it is a CSS file
		if checkPostfix("css", join) {
			if !RESULTS.CSS[join] {
				RESULTS.CSS[join] = true
			}
			continue
		}
		urparse, err := url.Parse(join)
		if err != nil {
			continue
		}
		// If the URL is out from scope
		if isOutScope(urparse.Host) {
			if !RESULTS.OutScopeURLs[join] {
				RESULTS.OutScopeURLs[join] = true
			}
			continue
		}
		// Clean the URL
		join = setURLUniq(join)
		if len(urparse.Query()) > 0 {
			RESULTS.QueryURLs[join] = true
		}
		// Add URL to URLs and output URLs
		if !RESULTS.URLs[join] {
			RESULTS.URLs[join] = true
		}
		uniq(&spool, join)
	}
	return spool
}