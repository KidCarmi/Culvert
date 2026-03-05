package main

import (
	"io"
	"log"
	"os"
	"sync"
)

// rotatingFile wraps a log file and rotates it when it exceeds maxBytes.
type rotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	size     int64
}

func newRotatingFile(path string, maxMB int) (*rotatingFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	info, _ := f.Stat()
	var sz int64
	if info != nil {
		sz = info.Size()
	}
	maxBytes := int64(maxMB) * 1024 * 1024
	if maxBytes == 0 {
		maxBytes = 50 * 1024 * 1024 // 50 MB default
	}
	return &rotatingFile{path: path, maxBytes: maxBytes, file: f, size: sz}, nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.size+int64(len(p)) > r.maxBytes {
		r.file.Close()
		os.Rename(r.path, r.path+".1")
		f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return 0, err
		}
		r.file = f
		r.size = 0
	}

	n, err := r.file.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) Close() error {
	return r.file.Close()
}

func setupLogger(logPath string, maxMB int) (*log.Logger, io.Closer, error) {
	writers := []io.Writer{os.Stdout}
	var closer io.Closer

	if logPath != "" {
		rf, err := newRotatingFile(logPath, maxMB)
		if err != nil {
			return nil, nil, err
		}
		writers = append(writers, rf)
		closer = rf
	}

	l := log.New(io.MultiWriter(writers...), "[ProxyShield] ", log.LstdFlags)
	return l, closer, nil
}
