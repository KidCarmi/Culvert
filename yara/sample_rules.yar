/*
 * ProxyShield Starter YARA Rules
 *
 * These rules are applied to HTTP response bodies flowing through the proxy.
 * Add your own .yar / .yara files to this directory and reload via:
 *   POST /api/security-scan/yara/reload
 *
 * References:
 *   https://yara.readthedocs.io/en/stable/writingrules.html
 *   https://github.com/Yara-Rules/rules  (community rule repository)
 */

// ── EICAR Test File ──────────────────────────────────────────────────────────
// The industry-standard antivirus test string. Detects the EICAR test file
// delivered over HTTP so you can verify ClamAV and YARA are both active.
rule EICAR_Test_File {
    meta:
        description = "EICAR antivirus test file"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
        severity    = "informational"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

// ── Web Shells ───────────────────────────────────────────────────────────────
// Common patterns found in PHP/ASP web shells delivered over HTTP.
rule WebShell_Generic_PHP {
    meta:
        description = "Generic PHP web shell indicators"
        severity    = "critical"
    strings:
        $eval_post   = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $system_post = /system\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
        $passthru    = /passthru\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
        $shell_exec  = /shell_exec\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
    condition:
        any of them
}

rule WebShell_China_Chopper {
    meta:
        description = "China Chopper web shell one-liner"
        severity    = "critical"
        reference   = "https://attack.mitre.org/software/S0020/"
    strings:
        $chopper = /eval\s*\(\s*base64_decode\s*\(\s*\$_(POST|GET)/ nocase
        $chopper2 = "e(base64_decode($_POST["
    condition:
        any of them
}

// ── Credential Harvesting ────────────────────────────────────────────────────
// JavaScript patterns used by phishing pages to steal credentials and
// exfiltrate them to attacker-controlled servers.
rule Phishing_Credential_Exfil {
    meta:
        description = "Credential harvesting / form data exfiltration script"
        severity    = "high"
    strings:
        // Fetching or XHR posting captured form data to an external host.
        $xfil1 = /document\.getElementById\(['"](password|passwd|pwd)['"]\)\.value/ nocase
        $xfil2 = /XMLHttpRequest.*\.open\s*\(.*POST/ nocase
        $xfil3 = /fetch\s*\(.*\{.*method.*POST/ nocase
    condition:
        $xfil1 and ($xfil2 or $xfil3)
}

// ── Malware Droppers ─────────────────────────────────────────────────────────
// PowerShell one-liners used by malware droppers delivered as HTML/JS payloads.
rule Dropper_PowerShell_DownloadString {
    meta:
        description = "PowerShell IEX DownloadString dropper pattern"
        severity    = "critical"
        reference   = "https://attack.mitre.org/techniques/T1059/001/"
    strings:
        $dl1 = "IEX(New-Object Net.WebClient).DownloadString" nocase
        $dl2 = "IEX (New-Object Net.WebClient).DownloadString" nocase
        $dl3 = /Invoke-Expression.*DownloadString/ nocase
        $dl4 = /\(New-Object\s+System\.Net\.WebClient\)\.DownloadFile/ nocase
    condition:
        any of them
}

rule Dropper_CertUtil_Decode {
    meta:
        description = "CertUtil living-off-the-land binary misuse for file download/decode"
        severity    = "high"
        reference   = "https://attack.mitre.org/techniques/T1140/"
    strings:
        $cu1 = "certutil -decode" nocase
        $cu2 = "certutil.exe -decode" nocase
        $cu3 = "certutil -urlcache -split -f" nocase
    condition:
        any of them
}

// ── Cryptocurrency Mining ────────────────────────────────────────────────────
// JavaScript crypto-miner code delivered to browsers via compromised pages.
rule CryptoMiner_CoinHive_Coinhive {
    meta:
        description = "Coinhive or generic in-browser cryptocurrency miner"
        severity    = "high"
    strings:
        $ch1 = "coinhive.com/lib/coinhive.min.js" nocase
        $ch2 = "CoinHive.Anonymous" nocase
        $ch3 = "CoinHive.User" nocase
        $ch4 = "cryptonight" nocase
        $wasm1 = "wasmresp" nocase
    condition:
        2 of them
}

// ── Suspicious Executables ───────────────────────────────────────────────────
// MZ / PE header in responses that are NOT declared as application/octet-stream.
// Useful for catching executables masquerading as images, documents, etc.
rule Suspicious_PE_In_Response {
    meta:
        description = "Windows PE (MZ) executable header in HTTP response"
        severity    = "medium"
    strings:
        $mz = { 4D 5A }  // "MZ" — DOS/PE header magic bytes
        $pe = { 50 45 00 00 }  // "PE\0\0" signature
    condition:
        $mz at 0 and $pe
}
