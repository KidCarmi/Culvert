package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/redaction"
)

// collectedStructs is every struct a Slice-1 support collector serializes into a
// section. The parity wall below asserts each EXPORTED field carries an explicit
// `redact:"<class>"` tag (or json:"-"). This is the load-bearing CI gate
// (REDACTION-MODEL §2): a new collected field cannot merge without a DataClass,
// mirroring the config_surfaces_test.go discipline. Extend this list whenever a
// collector serializes a new struct.
var collectedStructs = []any{
	productSection{},
	OperatorContract{},
	OperatorContractCheck{},
	healthReport{},
	readinessReport{},
	readinessCheck{},
}

func TestDataSurfaces_EveryCollectedFieldClassified(t *testing.T) {
	for _, s := range collectedStructs {
		rt := reflect.TypeOf(s)
		t.Run(rt.Name(), func(t *testing.T) {
			for i := 0; i < rt.NumField(); i++ {
				f := rt.Field(i)
				if !f.IsExported() || f.Tag.Get("json") == "-" {
					continue
				}
				tag := strings.TrimSpace(f.Tag.Get("redact"))
				if tag == "" {
					t.Errorf("%s.%s has no redact tag — classify it "+
						"public/internal/sensitive/secret/never_export (fail-closed gate)", rt.Name(), f.Name)
					continue
				}
				if _, ok := redaction.ParseClass(tag); !ok {
					t.Errorf("%s.%s has unknown redact class %q", rt.Name(), f.Name, tag)
				}
			}
		})
	}
}
