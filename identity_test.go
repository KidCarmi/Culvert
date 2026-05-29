package main

import "testing"

func TestIdentityAuthSource(t *testing.T) {
	tests := []struct {
		name     string
		id       *Identity
		fallback string
		want     string
	}{
		{
			name:     "provider wins",
			id:       &Identity{Provider: "profile-id"},
			fallback: "oidc:profile-id",
			want:     "profile-id",
		},
		{
			name:     "fallback for legacy provider",
			id:       &Identity{},
			fallback: "oidc:legacy",
			want:     "oidc:legacy",
		},
		{
			name:     "fallback for nil identity",
			id:       nil,
			fallback: "local",
			want:     "local",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := identityAuthSource(tt.id, tt.fallback); got != tt.want {
				t.Fatalf("identityAuthSource() = %q, want %q", got, tt.want)
			}
		})
	}
}
