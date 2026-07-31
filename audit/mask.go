package audit

import (
	"regexp"
	"strings"
)

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

	// reJWT matches a bare JSON Web Token: two required dot-separated base64url
	// segments (header, payload) plus an optional third (signature) — optional
	// because alg=none / unsigned JWTs still carry a plaintext claims payload
	// that must be masked even with an empty or absent signature segment.
	// Header and payload segments both decode to a JSON object, so in practice
	// they always start with the base64 encoding of `{"` — "eyJ" — which is
	// specific enough to anchor on without false-positiving on ordinary dotted
	// strings. Bearer-prefixed JWTs are already caught by reSecret; this
	// catches the rest (cookies, JSON body fields, unsigned tokens, logged
	// headers without the scheme prefix).
	reJWT = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]*)?\b`)

	// reGitHubToken matches GitHub's fixed vendor prefixes for PATs, OAuth, user-to-server,
	// server-to-server, and refresh tokens, plus the newer fine-grained github_pat_ format.
	reGitHubToken = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b`)

	// reGitLabToken matches GitLab personal access tokens.
	reGitLabToken = regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)

	// reStripeKey matches Stripe live secret/restricted keys. Stripe uses an
	// underscore separator ("sk_live_"), distinct from the existing dash-based
	// "sk-" pattern in reSecret, so this needs its own regex rather than an
	// alternation there.
	reStripeKey = regexp.MustCompile(`\b[sr]k_live_[A-Za-z0-9]{20,}\b`)

	// reNpmToken matches npm automation/publish tokens.
	reNpmToken = regexp.MustCompile(`\bnpm_[A-Za-z0-9]{30,}\b`)

	// reGoogleAPIKey matches Google API keys (fixed-length: AIza + 35 chars).
	reGoogleAPIKey = regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)

	// reAWSKeyID matches an AWS access key ID. The AKIA prefix + fixed 16-char
	// suffix is unique enough to a vendor credential that no length/context guard
	// beyond word boundaries is needed.
	reAWSKeyID = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)

	// reBasicAuth matches "Authorization: Basic <base64>" (colon or "="
	// separator — some loggers render headers as key=value pairs). Unlike
	// bearer/sk-, the word "basic" alone is ordinary English, so the match
	// requires the literal Authorization header context to avoid masking
	// prose ("a basic approach ..."). The header text is captured back out so
	// the replacement keeps the same "Authorization: [redacted]" shape as the
	// Bearer case.
	reBasicAuth = regexp.MustCompile(`(?i)(\bauthorization[:=]\s*)basic\s+[A-Za-z0-9+/]{8,}=*`)

	// reSlack matches Slack's xox{b,a,p,r,s}- prefixed token formats.
	reSlack = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)

	// reGenericSecret matches "<key><sep><value>" assignments for common secret
	// key names, case-insensitive, including JSON shape where the key is
	// quoted and the closing quote sits between the key word and the colon
	// (`"password":"hunter2"` — the optional `["']?` accounts for that quote).
	// The value must be quoted or a run of >=4 non-whitespace,
	// non-punctuation-delimiter chars — long enough to skip bare mentions
	// ("renew your token") but this still over-masks ordinary prose that
	// happens to use "secret"/"token" with a colon (e.g. "a secret: revealed
	// tomorrow"). Accepted tradeoff: fleet policy is over-masking beats leaking.
	reGenericSecret = regexp.MustCompile(`(?i)\b(?:api[_-]?key|password|passwd|secret|token|aws_secret_access_key)\b["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]{4,})`)

	// reCreditCardCandidate matches 13-19 digit runs (the PAN length range for
	// major card networks), optionally grouped with spaces or dashes. Luhn
	// validation (see maskCreditCards) gates the actual mask so arbitrary
	// same-length numeric IDs (order/invoice/tracking numbers) aren't shredded.
	// Note: rePhone below is intentionally broad and will already catch most
	// digit runs in this length range regardless of Luhn validity — this pass
	// exists to mask them specifically as card numbers before that happens, but
	// non-card digit runs may still end up masked via the phone pattern.
	reCreditCardCandidate = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
)

// luhnValid reports whether digits (a string of ASCII '0'-'9') passes the
// Luhn checksum used by major card networks.
func luhnValid(digits string) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// maskCreditCards redacts digit runs in reCreditCardCandidate that pass the
// Luhn check, leaving non-card-shaped runs (e.g. invoice numbers) untouched.
func maskCreditCards(s string) string {
	return reCreditCardCandidate.ReplaceAllStringFunc(s, func(m string) string {
		digits := strings.Map(func(r rune) rune {
			if r == ' ' || r == '-' {
				return -1
			}
			return r
		}, m)
		if luhnValid(digits) {
			return "[redacted]"
		}
		return m
	})
}

// MaskPII redacts identifiers and secrets in user-supplied text. Apply before
// persisting prompt bodies to the audit store; not a substitute for refusing
// to log obvious credentials in the first place.
//
// Order runs most-specific/vendor-anchored patterns first so a value that
// matches more than one shape (e.g. a JWT after "Bearer") is only replaced
// once, and so [redacted] output from an earlier pass never re-matches a
// later, looser pass — that also makes MaskPII idempotent: re-running it on
// already-masked text is a no-op, since "[redacted]" itself matches none of
// the patterns below.
func MaskPII(s string) string {
	if s == "" {
		return s
	}
	s = reSecret.ReplaceAllString(s, "[redacted]")
	s = reJWT.ReplaceAllString(s, "[redacted]")
	s = reGitHubToken.ReplaceAllString(s, "[redacted]")
	s = reGitLabToken.ReplaceAllString(s, "[redacted]")
	s = reStripeKey.ReplaceAllString(s, "[redacted]")
	s = reNpmToken.ReplaceAllString(s, "[redacted]")
	s = reGoogleAPIKey.ReplaceAllString(s, "[redacted]")
	s = reAWSKeyID.ReplaceAllString(s, "[redacted]")
	s = reBasicAuth.ReplaceAllString(s, "${1}[redacted]")
	s = reSlack.ReplaceAllString(s, "[redacted]")
	s = reGenericSecret.ReplaceAllString(s, "[redacted]")
	s = reRRN.ReplaceAllString(s, "[redacted]")
	s = maskCreditCards(s)
	s = reEmail.ReplaceAllString(s, "[redacted]")
	s = rePhone.ReplaceAllString(s, "[redacted]")
	return s
}
