// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: log <source> <message...>")
		os.Exit(1)
	}
	body := strings.ReplaceAll(strings.Join(os.Args[2:], " "), "\n", " ")
	msg := fmt.Sprintf("clampdown: %s %s: %s\n",
		time.Now().UTC().Format(time.RFC3339),
		os.Args[1], body)
	f, err := os.OpenFile("/proc/1/fd/2", os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		fmt.Fprint(os.Stderr, msg)
		os.Exit(0)
	}
	fmt.Fprint(f, msg)
	f.Close()
}
