## סיכום / Summary

<!-- תאר בקצרה מה השינוי הזה עושה ולמה / Briefly describe what this change does and why -->

**סוג שינוי / Change type:**
- [ ] `feat` — פיצ'ר חדש / new feature
- [ ] `fix` — תיקון באג / bug fix
- [ ] `security` — תיקון אבטחה / security fix
- [ ] `refactor` — שיפור קוד ללא שינוי פונקציונלי / refactor
- [ ] `chore` — תחזוקה, תלויות / maintenance, dependencies
- [ ] `docs` — תיעוד בלבד / documentation only

---

## בדיקות שבוצעו / Testing Done

<!-- אילו בדיקות הרצת? / What tests did you run? -->

```bash
go test -race ./...
# הוסף פלט רלוונטי / add relevant output
```

---

## רשימת בדיקות לפני Merge / Pre-Merge Checklist

### קוד / Code Quality
- [ ] הרצתי `go vet ./...` ו-`go build ./...` בהצלחה
- [ ] הרצתי `golangci-lint run` מקומית והתמודדתי עם כל הממצאים
- [ ] אין קוד מת (dead code), `TODO`-ים שנשכחו, או `log.Printf` debug
- [ ] פונקציות ופרמטרים חדשים תועדו ב-comments
- [ ] לא הכנסתי ספריות חדשות ללא אישור (`go.mod` לא השתנה, או הסיבה מוסברת)

### אבטחה / Security
- [ ] **אין secrets, passwords, tokens, או keys** בקוד (גם לא ב-tests)
- [ ] קלט מהמשתמש מאומת לפני שימוש
- [ ] קבצים/נתיבים חדשים מאומתים (path traversal)
- [ ] אין `InsecureSkipVerify: true` חדש ללא `#nosec` מתועד
- [ ] שינויים ב-`auth*.go`, `ca.go`, `proxy.go` עברו בדיקה מעמיקה

### אם נגעת ב-Policy Engine
- [ ] בדקתי שכל הרולות הקיימות עדיין עובדות (אין regression)
- [ ] בדקתי התנהגות default-deny / default-allow

### אם נגעת ב-Frontend (index.html)
- [ ] אין שימוש ב-`innerHTML` עם נתונים שמגיעים מהשרת ללא sanitization
- [ ] `textContent` במקום `innerHTML` לטקסט דינמי
- [ ] ב-Content-Security-Policy אין הרחבת `unsafe-inline` חדשה

### תיעוד / Documentation
- [ ] עדכנתי `CHANGELOG.md` (אם שינוי פונקציונלי)
- [ ] עדכנתי `config.example.yaml` (אם הוספתי שדה חדש ל-config)
- [ ] עדכנתי `SECURITY_RELEASE_PROCEDURE.md` (אם שיניתי את נוהל ה-release)

---

## סיכון ו-Rollback / Risk & Rollback

**רמת סיכון / Risk level:** 🟢 Low | 🟡 Medium | 🔴 High

**תוכנית Rollback:**
<!-- איך מחזירים לאחור אם יש בעיה / How to revert if something breaks -->

---

## Screenshots (אם רלוונטי ל-UI)

<!-- הוסף screenshots לפני/אחרי / Add before/after screenshots -->

---

## קישורים / Links

<!-- Issue: # -->
<!-- Related PR: # -->
