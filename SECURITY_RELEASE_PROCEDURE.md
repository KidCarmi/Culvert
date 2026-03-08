# נוהל אבטחה לפני שחרור גרסה — ProxyShield
# Security Release Procedure

> **מדיניות:** אסור לשחרר גרסה (`git tag v*`) מבלי שכל שלבי הנוהל הזה הושלמו בהצלחה.
> **Policy:** No release tag (`v*`) may be published unless all steps in this procedure have passed.

---

## 1. מבנה ה-Gate האוטומטי / Automated Gate Architecture

```
git push origin v1.2.3
        │
        ▼
┌─────────────────────────────────────────────────────┐
│          security-release-gate.yml                   │
│                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │ gosec (SAST)│  │ govulncheck  │  │ trivy src │  │
│  └─────────────┘  └──────────────┘  └───────────┘  │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │trivy (image)│  │   gitleaks   │  │ licenses  │  │
│  └─────────────┘  └──────────────┘  └───────────┘  │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │staticcheck  │  │ tests + race │  │ SBOM syft │  │
│  └─────────────┘  └──────────────┘  └───────────┘  │
│                          │                          │
│                   ┌──────▼───────┐                  │
│                   │release-approved│  ← required    │
│                   └──────────────┘    status check  │
└─────────────────────────────────────────────────────┘
        │ (only if gate passes)
        ▼
   ci.yml → release job (multi-platform build + GitHub Release)
```

---

## 2. רשימת בדיקות אבטחה / Security Check Inventory

| # | כלי / Tool | קטגוריה | מה הוא בודק | חסימה |
|---|-----------|---------|-------------|--------|
| 1 | **gosec** | SAST | ממצאים נפוצים ב-Go: SQL injection, command injection, weak crypto, path traversal | ✅ חוסם |
| 2 | **govulncheck** | CVE | פגיעויות ידועות (OSV/NVD) בקוד ובתלויות Go | ✅ חוסם |
| 3 | **trivy (source)** | CVE | סריקת go.sum וחבילות מערכת — CRITICAL/HIGH חוסמים | ✅ חוסם |
| 4 | **trivy (Docker image)** | CVE | סריקת Image הסופי — CRITICAL/HIGH חוסמים | ✅ חוסם |
| 5 | **gitleaks** | Secrets | זיהוי מפתחות, טוקנים, סיסמאות ב-commit history | ✅ חוסם |
| 6 | **go-licenses** | License | GPL/AGPL/LGPL ב-dependencies אסורים | ✅ חוסם |
| 7 | **staticcheck** | SAST | באגים לוגיים, קוד מת, API לא נכון | ✅ חוסם |
| 8 | **tests + race** | Quality | כיסוי קוד ≥ 60%, ללא race conditions | ✅ חוסם |
| 9 | **syft (SBOM)** | Transparency | יצירת Software Bill of Materials ב-CycloneDX | ℹ️ לא חוסם |

---

## 3. תהליך שחרור גרסה צעד-אחר-צעד / Step-by-Step Release Process

### שלב 1 — בדיקות מקומיות לפני push
```bash
# הרץ ידנית לפני כל tag
go build ./...
go vet ./...
go test -race -count=1 ./...

# סרוק secrets בקוד המקומי
gitleaks detect --source . --no-git

# בדוק פגיעויות
govulncheck ./...
```

### שלב 2 — עדכון CHANGELOG ו-version
```bash
# עדכן CHANGELOG.md עם כל השינויים
# עדכן את הגרסה ב-main.go אם קיים const version
git add CHANGELOG.md
git commit -m "chore: prepare release v1.2.3"
```

### שלב 3 — push tag ← מפעיל את ה-Gate
```bash
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3
```

### שלב 4 — מעקב ב-GitHub Actions
1. פתח: `https://github.com/<org>/Claude-Test/actions`
2. חכה לסיום workflow: **Security Release Gate**
3. **אם כל ה-jobs ירוקים** → job `release-approved` עובר → `ci.yml` משחרר אוטומטית
4. **אם job נכשל** → ראה שלב 5

### שלב 5 — תיקון כשל ב-Gate
```
כשל gosec       → תקן את הממצא בקוד, commit, push tag חדש
כשל govulncheck → עדכן dependency: go get -u <module>@<fixed-version>
כשל trivy       → עדכן base image ב-Dockerfile, או dependency פגיע
כשל gitleaks    → הסר secret מ-history (git filter-repo), rotate הטוקן
כשל licenses    → החלף dependency לחלופה עם MIT/Apache/BSD
כשל tests       → תקן הבאג ו/או הוסף בדיקות להגדיל coverage
```

---

## 4. הגדרת Branch Protection (חובה) / Required Branch Protection

```
Repository → Settings → Branches → main → Edit
☑ Require status checks to pass before merging
  Required checks:
    ✅ Security Gate — APPROVED
    ✅ Test & Build
☑ Require branches to be up to date before merging
☑ Restrict pushes that create matching branches (for tag pattern v*)
```

---

## 5. ניהול ממצאים / Finding Management

### חומרה ועדיפות / Severity & Priority

| חומרה | SLA תיקון |
|-------|-----------|
| **CRITICAL** | תיקון מיידי — לא ניתן לשחרר גרסה |
| **HIGH** | תיקון לפני release הבא |
| **MEDIUM** | תיקון ב-sprint הנוכחי |
| **LOW/INFO** | backlog — בדוק ב-release הבא |

### פתיחת Issue אבטחה
כאשר gate נכשל, פתח Issue עם template זה:

```markdown
## Security Finding — [gosec/trivy/gitleaks/...]

**חומרה / Severity:** CRITICAL / HIGH / MEDIUM
**כלי / Tool:**
**קובץ / File:**
**תיאור / Description:**

**השפעה / Impact:**

**תיקון מוצע / Proposed Fix:**

**Blocking release:** yes / no
```

---

## 6. ניהול Secrets / Secret Management Rules

- **אסור** לשמור secrets ב-`config.yaml` — השתמש במשתני סביבה
- `PROXYSHIELD_CA_PASSPHRASE` — env var בלבד (מתועד ב-`main.go:17`)
- LDAP `bind_password` ו-OIDC `client_secret` — הוצא ל-secrets manager
- SBOM מתפרסם עם כל release לשקיפות supply-chain

---

## 7. סריקה תקופתית / Scheduled Scanning

הוסף לסוף `security-release-gate.yml`:
```yaml
on:
  schedule:
    - cron: '0 3 * * 1'  # כל יום שני 03:00 UTC
```
כך פגיעויות חדשות יתגלו גם ללא שחרור גרסה.

---

## 8. Artifacts שנשמרים לכל Release

| Artifact | שמירה | תיאור |
|----------|-------|-------|
| `proxyshield-sbom.json` | 90 יום | Software Bill of Materials (CycloneDX) |
| `coverage.out` | 30 יום | דוח כיסוי בדיקות |
| `license-report.txt` | 30 יום | רשימת רישיונות תלויות |
| `gosec-results.sarif` | GitHub Security tab | ממצאי SAST |
| `trivy-*.sarif` | GitHub Security tab | ממצאי CVE |

---

*נוהל זה מתעדכן עם כל שינוי מהותי בתשתית האבטחה.*
*This procedure is updated with every significant change to the security infrastructure.*
