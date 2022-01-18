package main

import (
	"fmt"

	"github.com/iangcarroll/cookiemonster/pkg/monster"
)

func handleCookie() {
	// Attempt to decode this cookie.
	cookie := monster.NewCookie(*cookieFlag)

	if !cookie.Decode() {
		failureMessage("Sorry, I could not decode this cookie; it's likely not in a supported format.")
	}

	if *verboseFlag {
		fmt.Println(cookie.String())
	}

	// Load the appropriate wordlist.
	wl := loadWordlist()

	// Try to unsign the cookie.
	if _, success := cookie.Unsign(wl, uint64(*concurrencyFlag)); success {
		keyDiscoveredMessage(cookie)
	} else {
		failureMessage("Sorry, I did not discover the key for this cookie.")
	}

	handleResign(cookie)
}
