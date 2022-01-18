package main

import "github.com/iangcarroll/cookiemonster/pkg/monster"

func handleResign(cookie *monster.Cookie) {
	if *resignFlag != "" {
		if resigned := cookie.Resign(*resignFlag); resigned != "" {
			resignedMessage(resigned)
		} else {
			failureMessage("Sorry, I was unable to resign this cookie for you. It may not be supported for this decoder.")
		}
	}
}
