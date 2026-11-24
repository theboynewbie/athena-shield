package waf

import (
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

const DeepNormalizeMaxChars = 512 * 1024 // 512KB cap for deep judol normalization

var jsonUnicodeEscapeRe = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)

func isInvisibleRune(r rune) bool {
	switch {
	case r == 0x00ad || r == 0x034f || r == 0x061c || r == 0x115f || r == 0x1160 || r == 0x17b4 || r == 0x17b5 || r == 0x180e || r == 0x3164 || r == 0xfeff || r == 0xffa0:
		return true
	case r >= 0x200b && r <= 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e:
		return true
	case r >= 0x2060 && r <= 0x2064:
		return true
	case r >= 0x206a && r <= 0x206f:
		return true
	case r >= 0xfe00 && r <= 0xfe0f:
		return true
	}
	return false
}

func mapHomoglyph(r rune) rune {
	switch r {
	case 'а', 'А', 'α', 'Α', 'ɑ':
		return 'a'
	case 'в', 'В', 'β', 'Β':
		return 'b'
	case 'с', 'С':
		return 'c'
	case 'ԁ':
		return 'd'
	case 'е', 'Е', 'ё', 'ε', 'Ε':
		return 'e'
	case 'ց', 'ɡ':
		return 'g'
	case 'һ', 'Н', 'Η':
		return 'h'
	case 'і', 'І', 'ӏ', 'ι', 'Ι', 'ı':
		return 'i'
	case 'ј', 'Ј':
		return 'j'
	case 'к', 'К', 'κ', 'Κ':
		return 'k'
	case 'ʟ':
		return 'l'
	case 'м', 'М', 'Μ':
		return 'm'
	case 'п', 'η', 'Ν':
		return 'n'
	case 'о', 'О', 'ο', 'Ο', 'օ', 'ᴏ':
		return 'o'
	case 'р', 'Р', 'ρ', 'Ρ':
		return 'p'
	case 'ԛ':
		return 'q'
	case 'г':
		return 'r'
	case 'ѕ', 'Ѕ', 'ꜱ':
		return 's'
	case 'т', 'Т', 'τ', 'Τ', 'ᴛ':
		return 't'
	case 'μ', 'υ':
		return 'u'
	case 'ν':
		return 'v'
	case 'ԝ', 'ѡ', 'ω':
		return 'w'
	case 'х', 'Х', 'χ', 'Χ':
		return 'x'
	case 'у', 'У', 'ү', 'ʏ', 'Υ':
		return 'y'
	case 'Ζ':
		return 'z'
	}
	return r
}

func mapLeet(r rune) rune {
	switch r {
	case '0':
		return 'o'
	case '1':
		return 'i'
	case '3':
		return 'e'
	case '4', '@':
		return 'a'
	case '5', '$':
		return 's'
	case '8':
		return 'b'
	}
	return r
}

func stripHTMLTagsFast(s string) string {
	if !strings.Contains(s, "<") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	inTag := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '<' {
			inTag = true
			continue
		}
		if ch == '>' && inTag {
			inTag = false
			continue
		}
		if !inTag {
			b.WriteByte(ch)
		}
	}
	return b.String()
}

func urlDecodeLayers(rawText string) []string {
	if !strings.Contains(rawText, "%") && !strings.Contains(rawText, "+") {
		return nil
	}
	var variants []string
	curr := rawText
	for i := 0; i < 3; i++ {
		decoded, err := url.QueryUnescape(curr)
		if err != nil || decoded == curr {
			break
		}
		variants = append(variants, decoded)
		curr = decoded
		if !strings.Contains(curr, "%") && !strings.Contains(curr, "+") {
			break
		}
	}
	return variants
}

// deepJudolNormalize performs a single-pass non-regex normalization for gambling keywords.
func deepJudolNormalize(text string) []string {
	t := text
	if strings.Contains(t, `\u`) {
		t = jsonUnicodeEscapeRe.ReplaceAllStringFunc(t, func(m string) string {
			if len(m) != 6 {
				return m
			}
			v, err := strconv.ParseInt(m[2:], 16, 32)
			if err != nil {
				return m
			}
			return string(rune(v))
		})
	}
	if strings.Contains(t, "&") {
		t = html.UnescapeString(html.UnescapeString(t))
	}
	if strings.Contains(t, "<") {
		t = stripHTMLTagsFast(t)
	}

	var normBuf strings.Builder
	var collapsedBuf strings.Builder
	normBuf.Grow(len(t))
	collapsedBuf.Grow(len(t))

	prevSpace := false
	for _, r := range t {
		if isInvisibleRune(r) {
			continue
		}
		r = unicode.ToLower(mapHomoglyph(r))
		normBuf.WriteRune(r)

		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			collapsedBuf.WriteRune(r)
			prevSpace = false
		} else if !prevSpace {
			collapsedBuf.WriteByte(' ')
			prevSpace = true
		}
	}

	normStr := normBuf.String()
	colStr := strings.TrimSpace(collapsedBuf.String())
	if colStr != "" && colStr != normStr {
		return []string{normStr, colStr}
	}
	return []string{normStr}
}

func applyLeetFast(s string) (string, bool) {
	hasLeet := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '0', '1', '3', '4', '5', '8', '@', '$':
			hasLeet = true
		}
		if hasLeet {
			break
		}
	}
	if !hasLeet {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		b.WriteRune(mapLeet(r))
	}
	return b.String(), true
}

func NormalizeTextPayload(rawText string, includeLeetspeak bool) []string {
	if rawText == "" {
		return nil
	}
	variants := make([]string, 0, 6)
	variants = append(variants, rawText)
	if dec := urlDecodeLayers(rawText); len(dec) > 0 {
		variants = append(variants, dec...)
	}

	if includeLeetspeak {
		baseCount := len(variants)
		for i := 0; i < baseCount; i++ {
			item := variants[i]
			if len(item) > DeepNormalizeMaxChars {
				item = item[:DeepNormalizeMaxChars]
			}
			variants = append(variants, deepJudolNormalize(item)...)
		}
		curCount := len(variants)
		for i := 0; i < curCount; i++ {
			if leet, changed := applyLeetFast(variants[i]); changed {
				variants = append(variants, leet)
			}
		}
	}

	if len(variants) <= 1 {
		return variants
	}
	seen := make(map[string]struct{}, len(variants))
	unique := make([]string, 0, len(variants))
	for _, v := range variants {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			unique = append(unique, v)
		}
	}
	return unique
}
