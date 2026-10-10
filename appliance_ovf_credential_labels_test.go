package main

import (
	"bufio"
	"encoding/xml"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// The deploy wizard is the operator's only explanation of the two credential
// fields. An operator who read them as an SSH user and password got no SSH at
// all (no key ⇒ SSH off) and a password that only works on the VM console
// (#1528). These tests tie the wording to what sshd and first boot enforce, so
// a change on either side fails here instead of misleading the next operator.

type ovfProperty struct {
	Key         string `xml:"key,attr"`
	Label       string `xml:"Label"`
	Description string `xml:"Description"`
}

func ovfProperties(t *testing.T) map[string]ovfProperty {
	t.Helper()
	raw, err := os.ReadFile("appliance/build/culvert-appliance.ovf.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	doc := regexp.MustCompile(`@@[A-Z_]+@@`).ReplaceAllString(string(raw), "x")
	dec := xml.NewDecoder(strings.NewReader(doc))
	props := map[string]ovfProperty{}
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "Property" {
			var p ovfProperty
			if err := dec.DecodeElement(&p, &se); err != nil {
				t.Fatal(err)
			}
			props[p.Key] = p
		}
	}
	return props
}

// sshdDirective returns the value of one directive in the appliance's sshd drop-in.
func sshdDirective(t *testing.T, name string) string {
	t.Helper()
	f, err := os.Open("appliance/provision/sshd-50-culvert.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && fields[0] == name {
			return fields[1]
		}
	}
	t.Fatalf("sshd drop-in has no %s", name)
	return ""
}

func TestOVFCredentialLabels_MatchTheEnforcedSSHPosture(t *testing.T) {
	props := ovfProperties(t)
	key, pass := props["public-keys"], props["password"]
	if key.Key == "" || pass.Key == "" {
		t.Fatal("OVF lost the public-keys or password property")
	}
	sshUser := sshdDirective(t, "AllowUsers")
	if sshdDirective(t, "PasswordAuthentication") != "no" || sshdDirective(t, "AuthenticationMethods") != "publickey" {
		t.Fatal("sshd accepts something other than a key: the OVF wording below would then be false")
	}
	// The key field names the account SSH actually admits, says it is key-only
	// and public, and says what an empty field means.
	for _, want := range []string{sshUser, "key-only", "SSH off"} {
		if !strings.Contains(key.Label, want) {
			t.Errorf("public-keys label %q does not say %q", key.Label, want)
		}
	}
	for _, want := range []string{"PUBLIC", "private key never leaves", "ssh " + sshUser + "@", "never a password", "read-only"} {
		if !strings.Contains(key.Description, want) {
			t.Errorf("public-keys description does not say %q", want)
		}
	}
	// The password field must never read as an SSH credential.
	if !strings.Contains(pass.Label, "VM console") || !strings.Contains(pass.Label, "not for SSH") {
		t.Errorf("password label %q does not say it is VM-console only", pass.Label)
	}
	if !strings.Contains(pass.Description, "never accepted over SSH") {
		t.Error("password description does not say it is never accepted over SSH")
	}
	if strings.Contains(pass.Label, sshUser) {
		t.Errorf("password label names the SSH account %q", sshUser)
	}
}

// First boot mints a one-time console password whenever no password was set,
// whether or not a key was supplied; the wizard and the install guide must say
// so (the guide once said "only when no key is given either").
func TestOVFCredentialLabels_OneTimePasswordIsIndependentOfKeys(t *testing.T) {
	// Run the real console_policy: no password set, with and without a key.
	for _, keys := range []string{"0", "1"} {
		script := `eval "$(sed -n '/^console_policy() {/,/^}/p' appliance/provision/culvert-firstboot.sh)"; console_policy '' "$1" 0`
		out, err := exec.CommandContext(t.Context(), "bash", "-c", script, "_", keys).Output() // #nosec G204 -- fixed test script; keys is a literal "0"/"1"
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(out)); got != "mint" {
			t.Fatalf("console_policy with keys=%s and no password = %q, want mint; re-check the OVF wording", keys, got)
		}
	}
	if !strings.Contains(ovfProperties(t)["password"].Description, "even when an SSH public key is supplied") {
		t.Error("password description does not say a one-time password is shown even with a key")
	}
	guide, err := os.ReadFile("docs/appliance/hypervisor-install.md")
	if err != nil {
		t.Fatal(err)
	}
	g := string(guide)
	for _, stale := range []string{"for the `culvert` administrator", "only when no key is given either", "when no\nkey and no password were supplied"} {
		if strings.Contains(g, stale) {
			t.Errorf("hypervisor-install.md still says %q", stale)
		}
	}
	if !strings.Contains(g, "read-only `culvert-operator`") {
		t.Error("hypervisor-install.md does not name the read-only SSH account")
	}
}
