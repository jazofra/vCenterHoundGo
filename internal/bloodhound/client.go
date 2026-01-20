package bloodhound

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	URL       string
	KeyID     string
	KeySecret string
	Client    *http.Client
}

func NewClient(url, keyID, keySecret string) *Client {
	// Normalize URL
	url = strings.TrimRight(url, "/")

	return &Client{
		URL:       url,
		KeyID:     keyID,
		KeySecret: keySecret,
		Client:    &http.Client{Timeout: 30 * time.Second},
	}
}

// GetDomainMap retrieves domains from BloodHound and returns map[NetBIOS]FQDN
func (c *Client) GetDomainMap() (map[string]string, error) {
	req, _ := http.NewRequest("GET", c.URL+"/api/v2/available-domains", nil)

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to list available domains, status: %d", resp.StatusCode)
	}

	// The /available-domains endpoint typically returns a simple list of strings or objects.
	// Based on standard BloodHound API patterns, let's assume it returns { "data": [ "DOMAIN.COM", ... ] }
	// or similar. Let's handle generic structure or assume similar to previous attempt.
	// Reference [66] implies it returns the available domains.

	var apiResponse struct {
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, err
	}

	domainMap := make(map[string]string)
	for _, d := range apiResponse.Data {
		fqdn := strings.ToUpper(d.Name)
		// Heuristic: NetBIOS is usually the first part of FQDN.
		parts := strings.Split(fqdn, ".")
		if len(parts) > 0 {
			netbios := parts[0]
			domainMap[netbios] = fqdn
		}
	}

	return domainMap, nil
}

// GetComputerMap fetches computers from BloodHound and returns map[hostname]objectid
// This uses the search API to look up computers
// Note: This does batch lookups using search queries for efficiency
func (c *Client) GetComputerMap(domains []string) (map[string]string, error) {
	computerMap := make(map[string]string)

	// We can't bulk-fetch all computers, but we can search by domain suffix
	// The search API returns computers matching a query
	// We'll do a wildcard-like search for each domain
	for _, domain := range domains {
		skip := 0
		limit := 1000

		for {
			// Search for computers in this domain using the search API
			// Use the domain name as search query to find computers
			searchURL := fmt.Sprintf("%s/api/v2/search?q=.%s&limit=%d&skip=%d", c.URL, strings.ToLower(domain), limit, skip)
			req, _ := http.NewRequest("GET", searchURL, nil)

			resp, err := c.Do(req)
			if err != nil {
				return nil, fmt.Errorf("failed to search computers for domain %s: %v", domain, err)
			}

			if resp.StatusCode != 200 {
				bodyBytes, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				return nil, fmt.Errorf("failed to search computers for domain %s, status: %d, body: %s", domain, resp.StatusCode, string(bodyBytes))
			}

			var searchResponse struct {
				Data []struct {
					ObjectID          string `json:"objectid"`
					Type              string `json:"type"`
					Name              string `json:"name"`
					DistinguishedName string `json:"distinguishedname"`
				} `json:"data"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&searchResponse); err != nil {
				resp.Body.Close()
				return nil, fmt.Errorf("failed to decode search response for domain %s: %v", domain, err)
			}
			resp.Body.Close()

			if len(searchResponse.Data) == 0 {
				break
			}

			for _, item := range searchResponse.Data {
				if item.Type == "Computer" && strings.HasSuffix(strings.ToUpper(item.Name), strings.ToUpper(domain)) {
					name := strings.ToUpper(item.Name)
					hostname := strings.Split(name, ".")[0]
					computerMap[hostname] = item.ObjectID
					computerMap[name] = item.ObjectID
				}
			}

			// If we got fewer results than limit, we've reached the end
			if len(searchResponse.Data) < limit {
				break
			}
			skip += limit
		}
	}

	return computerMap, nil
}

// Do performs the request with authentication (Signed Request)
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if err := c.signRequest(req); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) signRequest(req *http.Request) error {
	// Timestamp (RFC3339)
	ts := time.Now().Format(time.RFC3339)

	// 1. H1 = HMAC(Key, Method + URI)
	// Method + URI (e.g., GET/api/v2/domains)
	// Note: URI should include the path relative to the host, including query params if any.
	// req.URL.Path should suffice if URL parsing was correct.
	// If NewRequest was created with full URL, req.URL.Path is the path.

	// Ensure we have a clean path
	uri := req.URL.Path
	if req.URL.RawQuery != "" {
		uri += "?" + req.URL.RawQuery
	}

	h1 := hmac.New(sha256.New, []byte(c.KeySecret))
	h1.Write([]byte(req.Method + uri))
	d1 := h1.Sum(nil)

	// 2. H2 = HMAC(H1, Timestamp[:13])
	// "2020-12-01T23" part
	if len(ts) < 13 {
		return fmt.Errorf("timestamp format error")
	}
	timePart := ts[:13]

	h2 := hmac.New(sha256.New, d1)
	h2.Write([]byte(timePart))
	d2 := h2.Sum(nil)

	// 3. H3 = HMAC(H2, Body) (if body exists)
	var d3 []byte
	if req.Body != nil {
		// We need to read body to sign it, then restore it.
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		// Restore body
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		h3 := hmac.New(sha256.New, d2)
		h3.Write(bodyBytes)
		d3 = h3.Sum(nil)
	} else {
		// Just use d2?
		// "In the case where there is no body content the HMAC digest is computed anyway, simply with no values written to the digester"
		h3 := hmac.New(sha256.New, d2)
		d3 = h3.Sum(nil)
	}

	signature := base64.StdEncoding.EncodeToString(d3)

	req.Header.Set("Authorization", fmt.Sprintf("bhesignature %s", c.KeyID))
	req.Header.Set("RequestDate", ts)
	req.Header.Set("Signature", signature)

	return nil
}
