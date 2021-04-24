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

// meta data
var VERSION = "0.1.2"
var STATUS_LINE_NAME  = fmt.Sprintf("[gocrawler/v%s]", VERSION)

