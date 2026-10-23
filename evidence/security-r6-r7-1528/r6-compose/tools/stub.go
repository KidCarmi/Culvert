package main

import (
	"os"
	"path/filepath"
	"time"
)

// Stand-in for the appliance images: makes no network calls. Invoked as
// clamdscan or wget (the compose healthchecks) it reports healthy; invoked
// with --list-backups (the cli run) it exits; otherwise it idles.
func main() {
	if filepath.Base(os.Args[0]) != "stub" {
		return
	}
	for _, a := range os.Args[1:] {
		if a == "--list-backups" {
			return
		}
	}
	time.Sleep(time.Hour)
}
