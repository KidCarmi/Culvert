package main

// backup_encrypt.go — package-main shim for the D1.4 backup-envelope crypto,
// moved to internal/backupcrypt (ADR-0002). The shims keep backup.go,
// restore.go, list_backups.go, main.go, and the test suite using the original
// unqualified names. See internal/backupcrypt for the on-disk format and the
// wrong-passphrase-vs-tamper opaque-error rationale.

import "github.com/KidCarmi/Culvert/internal/backupcrypt"

// Envelope/policy constants re-exposed unqualified.
const (
	backupEncMagic         = backupcrypt.Magic
	backupEncMagicLen      = backupcrypt.MagicLen
	backupEncHdrLen        = backupcrypt.HdrLen
	backupEncKDFIters      = backupcrypt.KDFIters
	backupPassphraseEnv    = backupcrypt.PassphraseEnv
	backupPassphraseMinLen = backupcrypt.PassphraseMinLen
)

// errBackupDecryptOpaque re-exposed for the restore path and the test suite
// (the engine var is backupcrypt.ErrDecryptOpaque — same underlying value, so
// errors.Is across the shim holds).
var errBackupDecryptOpaque = backupcrypt.ErrDecryptOpaque

// Crypto funcs re-exposed unqualified for backup.go / restore.go /
// list_backups.go and the test suite.
var (
	encryptBackupBlob     = backupcrypt.EncryptBlob
	decryptBackupBlob     = backupcrypt.DecryptBlob
	isEncryptedBackupBlob = backupcrypt.IsEncryptedBlob
	zeroBytes             = backupcrypt.ZeroBytes
)
