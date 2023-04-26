package main

import (
	"bufio"
	"fmt"
	"os"
)

func handleFile(filename string) {
	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		fmt.Printf("File %s does not exist\n", filename)
	    os.Exit(1)
	}

	// Open the file for reading
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	// Create a new scanner for the file
	scanner := bufio.NewScanner(file)

	// Loop through each line of the file
	for scanner.Scan() {
		line := scanner.Text()
		// Do something with each line here
        handleCookie(line)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println(err)
	}
}
