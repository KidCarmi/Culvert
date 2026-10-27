package main

import "unsafe"

// Kept in its own file so policy_scanindex_test.go needs no unsafe import.
func unsafeSizeofScanRow() uintptr    { return unsafe.Sizeof(policyScanRow{}) }
func unsafeSizeofPolicyRule() uintptr { return unsafe.Sizeof(PolicyRule{}) }
