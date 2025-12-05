package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mllamazares/webnose/pkg/models"
)

type Scanner struct {
	Client    *http.Client
	Templates []models.Template
	UserAgent string
}

func NewScanner(templates []models.Template, timeout int, userAgent string) *Scanner {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeout) * time.Second,
	}
	return &Scanner{
		Client:    client,
		Templates: templates,
		UserAgent: userAgent,
	}
}

func (s *Scanner) Scan(targetURL string) models.Result {
	// Ensure scheme
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		// Try HTTPS first
		res := s.scanURL("https://" + targetURL)
		if res.Error == "" {
			return res
		}
		// Fallback to HTTP
		return s.scanURL("http://" + targetURL)
	}
	return s.scanURL(targetURL)
}

func (s *Scanner) scanURL(targetURL string) models.Result {
	result := models.Result{
		URL:    targetURL,
		Smells: make(map[string]int),
	}

	// Extract subdomain
	u, err := url.Parse(targetURL)
	if err == nil {
		result.Subdomain = u.Hostname()
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("User-Agent", s.UserAgent)

	resp, err := s.Client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	body := string(bodyBytes)

	// Prepare headers string
	var headersBuilder strings.Builder
	for k, v := range resp.Header {
		headersBuilder.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
	}
	headersStr := headersBuilder.String()

	// Analyze
	for _, tmpl := range s.Templates {
		count := 0
		for _, matcher := range tmpl.Matchers {
			target := ""
			switch matcher.Part {
			case "url":
				target = targetURL
			case "body":
				target = body
			case "header":
				target = headersStr
			case "all":
				target = targetURL + "\n" + headersStr + "\n" + body
			default:
				target = body
			}

			matcherCount := 0
			for _, r := range matcher.Regex {
				re, err := regexp.Compile("(?i)" + r) // Default case insensitive for now to match Python logic mostly
				if !matcher.CaseInsensitive {
					re, err = regexp.Compile(r)
				}
				if err != nil {
					continue
				}
				matches := re.FindAllString(target, -1)
				matcherCount += len(matches)
			}

			if matcher.Negative {
				if matcherCount > 0 {
					count = 0
					break // Fail negative match
				}
				count++
			} else {
				count += matcherCount
			}
		}

		if count > 0 {
			result.Smells[tmpl.ID] = count
			result.RiskScore += tmpl.Info.RiskScore
		}
	}

	result.SmellCount = len(result.Smells)
	return result
}
