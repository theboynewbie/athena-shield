package waf

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
)

const (
	MaxDeepParseBytes  = 512 * 1024
	MaxJSONDepth       = 16
	MaxGraphQLDepth    = 12
	MaxExtractedFields = 512
	MaxExtractedChars  = 256 * 1024
)

// ExtractDeepTargets parses structured request payloads (JSON, GraphQL, XML, form-urlencoded, multipart)
// into inspectable targets while enforcing strict depth and size limits against DoS attacks.
// If a structural DoS violation is detected (e.g. JSON/GraphQL nesting bomb), it returns a non-empty violation reason.
func ExtractDeepTargets(contentType string, bodyBytes []byte, maxBytes int) ([]targetPair, string) {
	if len(bodyBytes) == 0 {
		return nil, ""
	}
	limit := MaxDeepParseBytes
	if maxBytes > 0 && maxBytes < limit {
		limit = maxBytes
	}
	slice := bodyBytes
	if len(slice) > limit {
		slice = slice[:limit]
	}

	ctLower := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	trimmed := bytes.TrimSpace(slice)

	// 1. GraphQL dedicated Content-Type
	if ctLower == "application/graphql" {
		q := string(slice)
		if checkGraphQLDepth(q) > MaxGraphQLDepth {
			return nil, "Protocol Hardening: GraphQL query nesting depth exceeds safe limit"
		}
		return []targetPair{{Name: "GraphQL Query", Value: q}}, ""
	}

	// 2. JSON (or JSON-like body)
	isJSON := ctLower == "application/json" || strings.HasSuffix(ctLower, "+json") ||
		(ctLower == "" && len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '['))
	if isJSON {
		return parseJSONDeep(slice)
	}

	// 3. XML
	isXML := ctLower == "application/xml" || ctLower == "text/xml" || strings.HasSuffix(ctLower, "+xml") ||
		(ctLower == "" && bytes.HasPrefix(trimmed, []byte("<")))
	if isXML {
		return parseXMLDeep(slice), ""
	}

	// 4. Form URL-Encoded
	if ctLower == "application/x-www-form-urlencoded" {
		return parseFormDeep(slice), ""
	}

	// 5. Multipart Form-Data
	if strings.HasPrefix(ctLower, "multipart/form-data") {
		return parseMultipartDeep(contentType, bodyBytes, limit), ""
	}

	return nil, ""
}

func parseJSONDeep(data []byte) ([]targetPair, string) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, ""
	}

	var vals []string
	var totalChars int
	var fields int

	var walk func(v any, depth int) bool
	walk = func(v any, depth int) bool {
		if depth > MaxJSONDepth {
			return false
		}
		if fields >= MaxExtractedFields || totalChars >= MaxExtractedChars {
			return true
		}
		switch node := v.(type) {
		case map[string]any:
			for k, val := range node {
				if fields >= MaxExtractedFields || totalChars >= MaxExtractedChars {
					break
				}
				if k != "" {
					vals = append(vals, k)
					totalChars += len(k)
					fields++
				}
				if !walk(val, depth+1) {
					return false
				}
			}
		case []any:
			for _, elem := range node {
				if fields >= MaxExtractedFields || totalChars >= MaxExtractedChars {
					break
				}
				if !walk(elem, depth+1) {
					return false
				}
			}
		case string:
			if node != "" {
				vals = append(vals, node)
				totalChars += len(node)
				fields++
			}
		}
		return true
	}

	if !walk(root, 1) {
		return nil, "Protocol Hardening: JSON nesting depth exceeds safe limit"
	}

	var targets []targetPair
	if obj, ok := root.(map[string]any); ok {
		if qStr, ok := obj["query"].(string); ok && strings.TrimSpace(qStr) != "" {
			if checkGraphQLDepth(qStr) > MaxGraphQLDepth {
				return nil, "Protocol Hardening: GraphQL query nesting depth exceeds safe limit"
			}
			targets = append(targets, targetPair{Name: "GraphQL Query", Value: qStr})
		}
	}
	if len(vals) > 0 {
		targets = append(targets, targetPair{Name: "JSON Field", Value: strings.Join(vals, " ")})
	}
	return targets, ""
}

func checkGraphQLDepth(q string) int {
	depth := 0
	maxDepth := 0
	inString := false
	escaped := false
	for i := 0; i < len(q); i++ {
		ch := q[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inString {
			escaped = true
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		if ch == '{' {
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		} else if ch == '}' && depth > 0 {
			depth--
		}
	}
	return maxDepth
}

func parseXMLDeep(data []byte) []targetPair {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var vals []string
	totalChars := 0
	fields := 0

	for fields < MaxExtractedFields && totalChars < MaxExtractedChars {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local != "" {
				vals = append(vals, t.Name.Local)
				totalChars += len(t.Name.Local)
				fields++
			}
			for _, attr := range t.Attr {
				if attr.Value != "" {
					vals = append(vals, attr.Name.Local+"="+attr.Value)
					totalChars += len(attr.Name.Local) + len(attr.Value) + 1
					fields++
				}
			}
		case xml.CharData:
			s := strings.TrimSpace(string(t))
			if s != "" {
				vals = append(vals, s)
				totalChars += len(s)
				fields++
			}
		}
	}
	if len(vals) == 0 {
		return nil
	}
	return []targetPair{{Name: "XML Field", Value: strings.Join(vals, " ")}}
}

func parseFormDeep(data []byte) []targetPair {
	vals, err := url.ParseQuery(string(data))
	if err != nil || len(vals) == 0 {
		return nil
	}
	var chunks []string
	totalChars := 0
	fields := 0
	for k, arr := range vals {
		for _, v := range arr {
			if fields >= MaxExtractedFields || totalChars >= MaxExtractedChars {
				break
			}
			item := k + "=" + v
			chunks = append(chunks, item)
			totalChars += len(item)
			fields++
		}
	}
	if len(chunks) == 0 {
		return nil
	}
	return []targetPair{{Name: "Form Field", Value: strings.Join(chunks, " ")}}
}

func parseMultipartDeep(contentType string, bodyBytes []byte, maxBytes int) []targetPair {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return nil
	}
	mr := multipart.NewReader(bytes.NewReader(bodyBytes), params["boundary"])
	var chunks []string
	totalChars := 0
	fields := 0

	for fields < MaxExtractedFields && totalChars < maxBytes && totalChars < MaxExtractedChars {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		fn := part.FileName()
		ct := strings.ToLower(part.Header.Get("Content-Type"))
		isSafeBin := false
		if fn != "" {
			fnLower := strings.ToLower(fn)
			hasSafeExt := false
			for _, ext := range safeBinaryExtensions {
				if strings.HasSuffix(fnLower, ext) {
					hasSafeExt = true
					break
				}
			}
			hasBinMIME := false
			for _, bm := range binaryMIMEs {
				if strings.Contains(ct, bm) {
					hasBinMIME = true
					break
				}
			}
			if hasSafeExt && hasBinMIME && !dangerousUploadRe.MatchString(fnLower) {
				isSafeBin = true
			}
		}
		if !isSafeBin {
			rem := maxBytes - totalChars
			if rem > 64*1024 {
				rem = 64 * 1024
			}
			buf, _ := io.ReadAll(io.LimitReader(part, int64(rem)))
			if s := strings.TrimSpace(string(buf)); s != "" {
				chunks = append(chunks, s)
				totalChars += len(s)
				fields++
			}
		}
		_ = part.Close()
	}
	if len(chunks) == 0 {
		return nil
	}
	return []targetPair{{Name: "Multipart Field", Value: strings.Join(chunks, " ")}}
}
