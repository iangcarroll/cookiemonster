package main

import (
	"fmt"

	"github.com/iangcarroll/cookiemonster/pkg/monster"
)

func handleCookie(cookieFlag string) {
	// Attempt to decode this cookie.
	cookie := monster.NewCookie(cookieFlag)

	if !cookie.Decode() {
		message := "Sorry, I could not decode this cookie; it's likely not in a supported format."
        fmt.Println(ColorRed + "❌ " + message + ColorReset)
        return
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
		message := "Sorry, I did not discover the key for this cookie."
        fmt.Println(ColorRed + "❌ " + message + ColorReset)
        return
	}

	handleResign(cookie)
}
