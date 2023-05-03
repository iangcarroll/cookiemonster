package main

import (
	"fmt"
	"os"

	"github.com/iangcarroll/cookiemonster/pkg/monster"
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
	_, key, decoder, jwt := cookie.Result()

	if isASCII(string(key)) {
		fmt.Printf(ColorGreen+"✅ Success! I discovered the key for %s with the %s decoder; it is \"%s\".\n"+ColorReset, jwt, decoder, string(key))
	} else {
		fmt.Printf(ColorGreen+"✅ Success! I discovered the key for %s with the %s decoder; it is (in base64): \"%s\"."+ColorReset, jwt, decoder, base64Key(key))
	}
}

// Output a nice success message if we decode the cookie.
func resignedMessage(out string) {
	fmt.Printf(ColorGreen+"✅ I resigned this cookie for you; the new one is: %s\n"+ColorReset, out)
}

func warningMessage(message string) {
	fmt.Printf(ColorYellow+"⚠️ %s\n"+ColorReset, message)
}
