package main

// client_class.go — package-main shim for the deterministic client classifier,
// moved to internal/clientclass (ADR-0002). The shims keep proxy.go and the
// test suite using the original unqualified names.

import "github.com/KidCarmi/Culvert/internal/clientclass"

// ClientClass and its values, re-exposed unqualified.
type ClientClass = clientclass.Class

const (
	clientNonBrowser = clientclass.NonBrowser
	clientBrowser    = clientclass.Browser
	clientConnect    = clientclass.Connect
)

// classifyClient / browserRedirectEligibleLegacy re-exposed for proxy.go and the
// test suite (engine funcs are clientclass.Classify / .BrowserRedirectEligibleLegacy).
var (
	classifyClient                = clientclass.Classify
	browserRedirectEligibleLegacy = clientclass.BrowserRedirectEligibleLegacy
)
