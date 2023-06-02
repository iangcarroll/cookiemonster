package main

import (
	"fmt"

	"github.com/iangcarroll/cookiemonster/pkg/monster"
)

func loadWordlist() *monster.Wordlist {
	wl := monster.NewWordlist()

	if *wordlistFlag == defaultWordlistKey {
		if err := wl.LoadDefault(); err != nil {
			failureMessage(fmt.Sprintf("Sorry, I could not load the default wordlist. Please report this to the maintainers. Error: %v", err))
		}

		fmt.Println("ℹ️  CookieMonster loaded the default wordlist; it has", wl.Count(), "entries.")
	} else {
		if err := wl.Load(*wordlistFlag); err != nil {
			failureMessage(fmt.Sprintf("Sorry, I could not load your wordlist. Please ensure every line contains valid base64. Error: %v", err))
		}

		fmt.Println("ℹ️  CookieMonster loaded your wordlist; it has", wl.Count(), "entries.")
	}

	return wl
}
