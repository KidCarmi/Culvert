// Command ldapstub runs the minimal LDAP responder (internal/ldapstub) for the
// browser smoke harness (frontend/scripts/e2e-smoke.sh): the appliance's
// enabled-LDAP writes cross the directory connection preflight at the write
// boundary unconditionally (FE-6A.2 correction, Blocker 3), so a journey
// that ENABLES an LDAP profile needs a directory that answers. Not wired
// into the main binary; never a production component.
//
//	ldapstub -listen 127.0.0.1:19389 [-reject-bind]
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/KidCarmi/Culvert/internal/ldapstub"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "address to listen on")
	reject := flag.Bool("reject-bind", false, "answer every authenticated bind with invalidCredentials")
	flag.Parse()
	s, err := ldapstub.Listen(*listen, ldapstub.Options{RejectBind: *reject})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ldapstub:", err)
		os.Exit(1)
	}
	fmt.Println(s.URL())
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	s.Close()
}
