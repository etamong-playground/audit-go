package audit

import "regexp"

var (
	// reEmail matches RFC-5321-ish local@host; intentionally lax — we only want to
	// notice when an email shows up in a prompt.
	reEmail = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	// rePhone matches Korean mobile (010-1234-5678 / 01012345678 / +82 10 …)
	// and generic E.164 (>=10 digits) without over-matching version strings.
	rePhone = regexp.MustCompile(`(?:\+?\d{1,3}[ \-]?)?(?:\(?\d{2,4}\)?[ \-]?){2,4}\d{3,4}`)
	// reRRN matches Korean resident registration numbers (YYMMDD-NNNNNNN).
	reRRN = regexp.MustCompile(`\b\d{6}-?\d{7}\b`)
	// reSecret matches "sk-..." style API keys and Bearer tokens.
	reSecret = regexp.MustCompile(`(?i)\b(?:sk-[A-Za-z0-9_\-]{16,}|bearer\s+[A-Za-z0-9._\-]{16,})`)
)

// MaskPII redacts identifiers and secrets in user-supplied text. Apply before
// persisting prompt bodies to the audit store; not a substitute for refusing
// to log obvious credentials in the first place.
func MaskPII(s string) string {
	if s == "" {
		return s
	}
	s = reSecret.ReplaceAllString(s, "[redacted]")
	s = reRRN.ReplaceAllString(s, "[redacted]")
	s = reEmail.ReplaceAllString(s, "[redacted]")
	s = rePhone.ReplaceAllString(s, "[redacted]")
	return s
}
