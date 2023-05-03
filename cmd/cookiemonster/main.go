package main

import (
	_ "embed"
	"flag"
	"os"
	"runtime"
)

const (
	version            = `1.4.1`
	defaultWordlistKey = `builtin`
)

var (
	cookieFlag      = flag.String("cookie", "", "Required unless using a URL. The cookie to attempt to decode and unsign.")
	urlFlag         = flag.String("url", "", "Required unless passing a cookie. An HTTP URL to retrieve cookies from instead of providing a cookie.")
	wordlistFlag    = flag.String("wordlist", defaultWordlistKey, "Optional. The path to load a base64-encoded wordlist from; the default is the `builtin` list.")
	concurrencyFlag = flag.Int("concurrency", runtime.NumCPU(), "Optional. How many attempts should run concurrently; the default is 100.")
	verboseFlag     = flag.Bool("verbose", false, "Optional. Enables additional output on how the cookie is decoded.")
	fileFlag        = flag.String("file", "", "Optional. Read cookies from the file.")
	resignFlag      = flag.String("resign", "", "Optional. Unencoded data to resign the cookie with; presently only supported by Django.")

	//go:embed wordlists/flask-unsign.txt
	defaultWordlist string
)

func main() {
	sayHello()
	flag.Parse()

	// We need both of these.
	if (*cookieFlag == "" && *urlFlag == "" && *fileFlag == "") || *wordlistFlag == "" {
		flag.Usage()
		os.Exit(1)
	}

	// file has the highest priority
	// followed by cookie and then url
	if *fileFlag != "" {
		handleFile(*fileFlag)
	}

	if *cookieFlag != "" {
		handleCookie(*cookieFlag)
	}

	if *urlFlag != "" {
		handleURL()
	}
}
