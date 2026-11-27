package main

// install_script_detect_distro_lmde_test.go — Linux Mint Debian Edition must
// get Docker's DEBIAN apt repo, not the Ubuntu one.
//
// detect_distro's explicit `linuxmint` arm rewrote every Mint to
// DISTRO_ID=ubuntu and took UBUNTU_CODENAME, falling back to VERSION_CODENAME.
// LMDE (ID=linuxmint, ID_LIKE=debian) carries no UBUNTU_CODENAME; its
// VERSION_CODENAME is the Mint name ("faye") and its base is DEBIAN_CODENAME
// ("bookworm"). The installer therefore wrote
//   deb … https://download.docker.com/linux/ubuntu faye stable
// a suite that does not exist, so `apt-get update` failed under `set -e` and the
// install aborted before Docker was installed. Uses runDetectDistro from
// install_script_detect_distro_debian_like_test.go.

import "testing"

func TestDetectDistro_LMDEUsesDebianRepo(t *testing.T) {
	const lmde6 = "PRETTY_NAME=\"LMDE 6 (faye)\"\nNAME=\"LMDE\"\nVERSION_ID=\"6\"\n" +
		"VERSION=\"6 (faye)\"\nVERSION_CODENAME=faye\nID=linuxmint\nID_LIKE=debian\n" +
		"DEBIAN_CODENAME=bookworm\n"
	if id, cn := runDetectDistro(t, lmde6); id != "debian" || cn != "bookworm" {
		t.Fatalf("LMDE 6: got docker repo linux/%s %s; want linux/debian bookworm", id, cn)
	}
}

// Mainline (Ubuntu-based) Mint must keep the Ubuntu repo and its Ubuntu base
// codename — the negative control for the LMDE branch.
func TestDetectDistro_MainlineMintKeepsUbuntuRepo(t *testing.T) {
	const mint21 = "NAME=\"Linux Mint\"\nVERSION=\"21.3 (Virginia)\"\nID=linuxmint\n" +
		"ID_LIKE=\"ubuntu debian\"\nVERSION_ID=\"21.3\"\nVERSION_CODENAME=virginia\n" +
		"UBUNTU_CODENAME=jammy\n"
	if id, cn := runDetectDistro(t, mint21); id != "ubuntu" || cn != "jammy" {
		t.Fatalf("Mint 21.3: got docker repo linux/%s %s; want linux/ubuntu jammy", id, cn)
	}
}
