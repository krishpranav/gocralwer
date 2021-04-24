# gocralwer
A awsome crawler made in go

[![forthebadge](https://forthebadge.com/images/badges/made-with-go.svg)](https://forthebadge.com)

### From GitHub
```
git clone https://github.com/krishpranav/gocralwer
cd evine
go build .
mv gocrawler /usr/local/bin
gocrawler --help
```

Note: golang 1.13.x required.

## Commands & Usage

Keybinding                              | Description
----------------------------------------|---------------------------------------
<kbd>Enter</kbd>                        | Run crawler (from URL view)
<kbd>Enter</kbd>                        | Display response (from Keys and Regex views)
<kbd>Tab</kbd>       					          | Next view
<kbd>Ctrl+Space</kbd>                   | Run crawler
<kbd>Ctrl+S</kbd>                       | Save response
<kbd>Ctrl+Z</kbd>                       | Quit
<kbd>Ctrl+R</kbd>                       | Restore to default values (from Options and Headers views)
<kbd>Ctrl+Q</kbd>                       | Close response save view (from Save view)

```bash
gocrawler -h
```
It will displays help for the tool:

| flag | Description | Example |
|------|-------------|---------|
| -url | URL to crawl for | gocrawler -url toscrape.com |
| -url-exclude string | Exclude URLs maching with this regex (default ".*")  | gocrawler -url-exclude ?id= | 
| -domain-exclude string | Exclude in-scope domains to crawl. Separate with comma. default=root domain | gocrawler -domain-exclude host1.tld,host2.tld | 
| -code-exclude string | Exclude HTTP status code with these codes. Separate whit '\|' (default ".*") | gocrawler -code-exclude 200,201 | 
| -delay int  | Sleep between each request(Millisecond) | gocrawler -delay 300 | 
| -depth | Scraper depth search level (default 1) | gocrawler -depth 2 | 
| -thread int | The number of concurrent goroutines for resolving (default 5) | gocrawler -thread 10 |
| -header | HTTP Header for each request(It should to separated fields by \n). | gocrawler -header KEY: VALUE\nKEY1: VALUE1 | 
| -proxy string | Proxy by scheme://ip:port | gocrawler -proxy http://1.1.1.1:8080 | 
| -scheme string | Set the scheme for the requests (default "https") | gocrawler -scheme http | 
| -timeout int | Seconds to wait before timing out (default 10) | gocrawler -timeout 15 | 
| -query string | JQuery expression(It could be a file extension(pdf), a key query(url,script,css,..) or a jquery selector($("a[class='hdr']).attr('hdr')"))) | evine -query url,pdf,txt |
| -regex string | Search the Regular Expression on the page contents | gocrawler -regex 'User.+' |
| -max-regex int | Max result of regex search for regex field (default 1000) | gocrawler -max-regex -1 | 
| -robots | Scrape robots.txt for URLs and using them as seeds | gocrawler -robots |
| -sitemap | Scrape sitemap.xml for URLs and using them as seeds | gocrawler -sitemap |
| -wayback | Scrape WayBackURLs(web.archive.org) for URLs and using them as seeds | gocrawler -sitemap |

