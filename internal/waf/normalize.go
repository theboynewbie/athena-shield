package waf

import (
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const DeepNormalizeMaxChars = 2 * 1024 * 1024

var (
	invisibleCharsRe    = regexp.MustCompile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0]")
	jsonUnicodeEscapeRe = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	htmlTagRe           = regexp.MustCompile(`(?s)<!--.*?-->|</?[a-zA-Z][^<>]{0,200}>`)
	separatorRe         = regexp.MustCompile(`[^\w\s]+|_+`)
	whitespaceRe        = regexp.MustCompile(`\s+`)

	homoglyphReplacer = strings.NewReplacer(
		"а", "a", "А", "a", "в", "b", "В", "b", "с", "c", "С", "c", "ԁ", "d", "е", "e", "Е", "e", "ё", "e",
		"һ", "h", "Н", "h", "і", "i", "І", "i", "ӏ", "i", "ј", "j", "Ј", "j", "к", "k", "К", "k", "м", "m",
		"М", "m", "п", "n", "о", "o", "О", "o", "р", "p", "Р", "p", "ԛ", "q", "г", "r", "ѕ", "s", "Ѕ", "s",
		"т", "t", "Т", "t", "у", "y", "У", "y", "х", "x", "Х", "x", "ԝ", "w", "ѡ", "w", "ү", "y", "ʏ", "y",
		"α", "a", "Α", "a", "β", "b", "Β", "b", "ε", "e", "Ε", "e", "η", "n", "Η", "h", "ι", "i", "Ι", "i",
		"κ", "k", "Κ", "k", "μ", "u", "Μ", "m", "ν", "v", "Ν", "n", "ο", "o", "Ο", "o", "ρ", "p", "Ρ", "p",
		"τ", "t", "Τ", "t", "υ", "u", "Υ", "y", "χ", "x", "Χ", "x", "ω", "w", "Ζ", "z", "ց", "g", "օ", "o",
		"ı", "i", "ɡ", "g", "ɑ", "a", "ʟ", "l", "ꜱ", "s", "ᴏ", "o", "ᴛ", "t",
	)

	leetReplacer = strings.NewReplacer(
		"0", "o", "1", "i", "3", "e", "4", "a", "5", "s", "8", "b", "@", "a", "$", "s",
	)
)

func urlDecodeLayers(rawText string) []string {
	var variants []string
	curr := rawText
	for i := 0; i < 3; i++ {
		decoded, err := url.QueryUnescape(curr)
		if err != nil {
			// Fallback: replace valid %XX sequences leniently or stop
			break
		}
		if decoded == curr {
			break
		}
		variants = append(variants, decoded)
		curr = decoded
	}
	return variants
}

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
	t = invisibleCharsRe.ReplaceAllString(t, "")
	if strings.Contains(t, "<") {
		t = htmlTagRe.ReplaceAllString(t, "")
	}
	t = strings.ToLower(homoglyphReplacer.Replace(t))

	out := []string{t}
	collapsed := whitespaceRe.ReplaceAllString(separatorRe.ReplaceAllString(t, " "), " ")
	if collapsed != t {
		out = append(out, collapsed)
	}
	return out
}

func NormalizeTextPayload(rawText string, includeLeetspeak bool) []string {
	if rawText == "" {
		return nil
	}
	variants := []string{rawText}
	variants = append(variants, urlDecodeLayers(rawText)...)

	if includeLeetspeak {
		var deep []string
		for _, item := range variants {
			if len(item) > DeepNormalizeMaxChars {
				item = item[:DeepNormalizeMaxChars]
			}
			deep = append(deep, deepJudolNormalize(item)...)
		}
		variants = append(variants, deep...)

		snapshot := make([]string, len(variants))
		copy(snapshot, variants)
		for _, item := range snapshot {
			translated := leetReplacer.Replace(item)
			if translated != item {
				variants = append(variants, translated)
			}
		}
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
