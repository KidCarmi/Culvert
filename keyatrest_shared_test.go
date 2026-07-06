package main

import "github.com/KidCarmi/Culvert/internal/secret"

// envKEKName aliases secret.EnvKEKName for the key-at-rest tests, which set the
// CULVERT_KEK environment variable by this name. The constant (and all the KEK
// primitives) moved into internal/secret when the compiler-enforced secret
// boundary was extracted (ADR-0007); this test-only alias keeps the existing
// key-at-rest tests referencing the canonical value without churn, and lets the
// package-main kek.go byte API be deleted entirely.
const envKEKName = secret.EnvKEKName
