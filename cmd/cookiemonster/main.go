package main

import (
	_ "embed"
	"flag"
	"fmt"
	"os"

	"github.com/iangcarroll/cookiemonster/pkg/monster"
)

const (
	version            = `1.0.0`
	defaultWordlistKey = `builtin`
)

var (
	cookieFlag      = flag.String("cookie", "", "Required. The cookie to attempt to decode and unsign.")
	wordlistFlag    = flag.String("wordlist", defaultWordlistKey, "Optional. The path to load a base64-encoded wordlist from; the default is the `builtin` list.")
	concurrencyFlag = flag.Int("concurrency", 100, "Optional. How many attempts should run concurrently; the default is 100.")
	verboseFlag     = flag.Bool("verbose", false, "Optional. Enables additional output on how the cookie is decoded.")
	resignFlag      = flag.String("resign", "", "Optional. Unencoded data to resign the cookie with; presently only supported by Django.")

	//go:embed wordlists/flask-unsign.txt
	defaultWordlist string
)

// Say hello!
func sayHello() {
	fmt.Println("🍪 CookieMonster", version)
}

// Output a sadder failure message if we cannot decode the cookie.
func failureMessage(message string) {
	fmt.Println(ColorRed + "❌ " + message + ColorReset)
	os.Exit(1)
}

// Output a nice success message if we decode the cookie.
func keyDiscoveredMessage(cookie *monster.Cookie) {
	_, key, decoder := cookie.Result()

	if isASCII(string(key)) {
		fmt.Printf(ColorGreen+"✅ Success! I discovered the key for this cookie with the %s decoder; it is \"%s\".\n"+ColorReset, decoder, string(key))
	} else {
		fmt.Printf(ColorGreen+"✅ Success! I discovered the key for this cookie with the %s decoder; it is (in base64): \"%s\"."+ColorReset, decoder, base64Key(key))
	}
}

// Output a nice success message if we decode the cookie.
func resignedMessage(out string) {
	fmt.Printf(ColorGreen+"✅ I resigned this cookie for you; the new one is: %s\n"+ColorReset, out)
}

func main() {
	sayHello()
	flag.Parse()

	// We need both of these.
	if *cookieFlag == "" || *wordlistFlag == "" {
		flag.Usage()
		os.Exit(1)
	}

	cookie := monster.NewCookie(*cookieFlag)
	if !cookie.Decode() {
		failureMessage("Sorry, I could not decode this cookie; it's likely not in a supported format.")
	}

	if *verboseFlag {
		fmt.Println(cookie.String())
	}

	wl := monster.NewWordlist()

	if *wordlistFlag == defaultWordlistKey {
		if err := wl.LoadFromString(defaultWordlist); err != nil {
			failureMessage(fmt.Sprintf("Sorry, I could not load the default wordlist. Please report this to the maintainers. Error: %v", err))
		}

		fmt.Println("ℹ️  CookieMonster loaded the default wordlist; it has", wl.Count(), "entries.")
	} else {
		if err := wl.Load(*wordlistFlag); err != nil {
			failureMessage(fmt.Sprintf("Sorry, I could not load your wordlist. Please ensure every line contains valid base64. Error: %v", err))
		}

		fmt.Println("ℹ️  CookieMonster loaded your wordlist; it has", wl.Count(), "entries.")
	}

	if _, success := cookie.Unsign(wl, uint64(*concurrencyFlag)); success {
		keyDiscoveredMessage(cookie)
	} else {
		failureMessage("Sorry, I did not discover the key for this cookie.")
	}

	if *resignFlag != "" {
		if resigned := cookie.Resign(*resignFlag); resigned != "" {
			resignedMessage(resigned)
		} else {
			failureMessage("Sorry, I was unable to resign this cookie for you. It may not be supported for this decoder.")
		}
	}
}
