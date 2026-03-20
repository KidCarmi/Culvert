package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// FileExtProfile is a named set of file extensions used for per-policy-rule blocking.
type FileExtProfile struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Extensions []string `json:"extensions"`
}

// FileProfileStore manages a persistent collection of file extension profiles.
// All operations are safe for concurrent use.
type FileProfileStore struct {
	mu       sync.RWMutex
	profiles []*FileExtProfile
	path     string
}

var globalProfileStore = &FileProfileStore{}

// builtInProfiles seeds the store on first use so existing policy rules that
// reference the legacy hardcoded profile names continue to work.
var builtInProfiles = []*FileExtProfile{
	{
		ID:   "builtin-executables",
		Name: "Executables",
		Extensions: []string{
			".exe", ".dll", ".bat", ".cmd", ".ps1",
			".scr", ".msi", ".pif", ".com", ".vbs",
		},
	},
	{
		ID:   "builtin-archives",
		Name: "Archives",
		Extensions: []string{
			".zip", ".rar", ".7z", ".tar", ".gz",
			".bz2", ".xz", ".cab", ".iso",
		},
	},
	{
		ID:   "builtin-documents",
		Name: "Documents",
		Extensions: []string{
			".docm", ".xlsm", ".pptm", ".xlam", ".dotm",
		},
	},
	{
		ID:   "builtin-media",
		Name: "Media",
		Extensions: []string{
			".mp3", ".mp4", ".avi", ".mkv", ".mov",
			".flv", ".wmv", ".webm",
		},
	},
	{
		ID:   "builtin-strict",
		Name: "Strict",
		Extensions: []string{
			".exe", ".dll", ".bat", ".cmd", ".ps1", ".scr", ".msi", ".pif", ".com", ".vbs",
			".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso",
			".docm", ".xlsm", ".pptm",
		},
	},
}

// Load reads profiles from disk. If the file does not exist the built-in
// profiles are seeded and persisted so policy rules continue to work.
func (s *FileProfileStore) Load(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// First run — seed built-ins and persist.
		s.profiles = make([]*FileExtProfile, len(builtInProfiles))
		copy(s.profiles, builtInProfiles)
		return s.saveLocked()
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.profiles)
}

func (s *FileProfileStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.profiles, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func (s *FileProfileStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// List returns a copy of all profiles.
func (s *FileProfileStore) List() []*FileExtProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*FileExtProfile, len(s.profiles))
	copy(out, s.profiles)
	return out
}

// GetByName returns the profile with the given name (case-insensitive), or nil.
func (s *FileProfileStore) GetByName(name string) *FileExtProfile {
	lower := strings.ToLower(name)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.profiles {
		if strings.ToLower(p.Name) == lower {
			return p
		}
	}
	return nil
}

// GetByID returns the profile with the given ID, or nil.
func (s *FileProfileStore) GetByID(id string) *FileExtProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.profiles {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// Create adds a new profile. Returns an error if the name is already taken.
func (s *FileProfileStore) Create(name string, exts []string) (*FileExtProfile, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("profile name must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lower := strings.ToLower(name)
	for _, p := range s.profiles {
		if strings.ToLower(p.Name) == lower {
			return nil, fmt.Errorf("profile %q already exists", name)
		}
	}
	prof := &FileExtProfile{
		ID:         uuid.NewString(),
		Name:       name,
		Extensions: normExts(exts),
	}
	s.profiles = append(s.profiles, prof)
	return prof, s.saveLocked()
}

// Update replaces the name and/or extensions of an existing profile.
func (s *FileProfileStore) Update(id, name string, exts []string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("profile name must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lower := strings.ToLower(name)
	for _, p := range s.profiles {
		if p.ID == id {
			// Check name uniqueness (allow keeping the same name).
			if strings.ToLower(p.Name) != lower {
				for _, other := range s.profiles {
					if other.ID != id && strings.ToLower(other.Name) == lower {
						return fmt.Errorf("profile %q already exists", name)
					}
				}
			}
			p.Name = name
			p.Extensions = normExts(exts)
			return s.saveLocked()
		}
	}
	return fmt.Errorf("profile %q not found", id)
}

// Delete removes a profile by ID.
func (s *FileProfileStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.profiles {
		if p.ID == id {
			s.profiles = append(s.profiles[:i], s.profiles[i+1:]...)
			return s.saveLocked()
		}
	}
	return fmt.Errorf("profile %q not found", id)
}

// normExts normalises a list of extensions to lowercase with a leading dot.
func normExts(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, e := range in {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || e == "." {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}
