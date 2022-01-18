package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/iangcarroll/cookiemonster/pkg/monster"
)

var (
	client = http.Client{
		Timeout: time.Second * 10,

		// We do not verify TLS certificates for ease of use, although we could
		// make this configurable in the future.
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},

		// We cannot easily follow redirects, as we don't have access to
		// the cookies in the redirect chain.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

func buildCookieMap(res *http.Response) map[string]*http.Cookie {
	cookieMap := make(map[string]*http.Cookie)

	for _, cookie := range res.Cookies() {
		cookieMap[cookie.Name] = cookie
	}

	return cookieMap
}

func checkCookie(wl *monster.Wordlist, value string) {
	c := monster.NewCookie(value)

	if !c.Decode() {
		return
	}

	if *verboseFlag {
		fmt.Println(c.String())
	}

	if _, success := c.Unsign(wl, uint64(*concurrencyFlag)); !success {
		return
	}

	keyDiscoveredMessage(c)
	handleResign(c)
	os.Exit(0)
}

func handleURL() {
	res, err := client.Get(*urlFlag)
	if err != nil {
		failureMessage(fmt.Sprintf("Could not request the URL you provided, got error: %v", err))
	}

	// Raise a warning if we encounter a non-200 status code.
	if res.StatusCode != 200 {
		warningMessage(fmt.Sprintf("I got a non-200 status code from this URL; it was %d.", res.StatusCode))
	}

	cookies := res.Cookies()

	// Exit early if we did not get any cookies.
	if len(cookies) == 0 {
		failureMessage("Sorry, I did not receive any cookies from that URL.")
	}

	// Load the wordlist once we know we have some cookies.
	wl := loadWordlist()

	// We build a map of the cookies to be able to search for
	// Express signature cookies.
	cookieMap := buildCookieMap(res)

	for _, cookie := range cookies {
		value := strings.TrimSpace(cookie.Value)
		sibling, hasSibling := cookieMap[cookie.Name+".sig"]

		if hasSibling {
			name := strings.TrimSpace(cookie.Name)

			// Library expects this in session=data^signature form.
			input := name + "=" + value + "^" + sibling.Value
			checkCookie(wl, input)
		}

		checkCookie(wl, value)
	}

	failureMessage(fmt.Sprintf("Sorry, I did not discover the key for this URL, out of %d cookies.", len(cookies)))
}
