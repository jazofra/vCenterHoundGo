package collector

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"vcenterhoundgo/internal/config"
)

// TagCollector handles REST API tag collection
type TagCollector struct {
	Config config.Config
	Logger *log.Logger
}

func NewTagCollector(cfg config.Config, logger *log.Logger) *TagCollector {
	return &TagCollector{
		Config: cfg,
		Logger: logger,
	}
}

// Debugf logs debug messages if enabled
func (tc *TagCollector) Debugf(format string, v ...any) {
	if tc.Config.Debug {
		tc.Logger.Printf("[DEBUG] "+format, v...)
	}
}

// Collect returns a map of moid -> []tagName
func (tc *TagCollector) Collect() map[string][]string {
	tc.Logger.Println("Collecting tags via REST API...")

	tagMap := make(map[string][]string)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	baseURL := fmt.Sprintf("https://%s/rest", tc.Config.Host)

	// Login
	req, _ := http.NewRequest("POST", baseURL+"/com/vmware/cis/session", nil)
	req.SetBasicAuth(tc.Config.User, tc.Config.Password)

	resp, err := client.Do(req)
	if err != nil {
		tc.Logger.Printf("REST API login failed: %v", err)
		return tagMap
	}

	if resp.StatusCode != 200 {
		tc.Logger.Printf("REST API login returned status: %d", resp.StatusCode)
		resp.Body.Close()
		return tagMap
	}

	var sessionResp struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sessionResp); err != nil {
		tc.Logger.Printf("Failed to decode session response: %v", err)
		resp.Body.Close()
		return tagMap
	}
	resp.Body.Close()
	sessionID := sessionResp.Value

	// Helper to make authenticated requests
	doReq := func(method, url string) (*http.Response, error) {
		r, err := http.NewRequest(method, url, nil)
		if err != nil {
			return nil, err
		}
		r.Header.Set("vmware-api-session-id", sessionID)
		return client.Do(r)
	}

	// 1. Get Categories
	catMap := make(map[string]string) // id -> name
	resp, err = doReq("GET", baseURL+"/com/vmware/cis/tagging/category")
	if err == nil {
		var catList struct {
			Value []string `json:"value"`
		}
		json.NewDecoder(resp.Body).Decode(&catList)
		resp.Body.Close()

		for _, catID := range catList.Value {
			resp, err := doReq("GET", fmt.Sprintf("%s/com/vmware/cis/tagging/category/%s", baseURL, catID))
			if err != nil {
				continue
			}
			var catInfo struct {
				Value struct {
					Name string `json:"name"`
				} `json:"value"`
			}
			json.NewDecoder(resp.Body).Decode(&catInfo)
			resp.Body.Close()
			if catInfo.Value.Name != "" {
				catMap[catID] = catInfo.Value.Name
			}
		}
	} else {
		tc.Logger.Printf("Failed to list tag categories: %v", err)
	}
	tc.Debugf("Found %d tag categories", len(catMap))

	// 2. Get Tags
	resp, err = doReq("GET", baseURL+"/com/vmware/cis/tagging/tag")
	if err != nil {
		tc.Logger.Printf("Failed to list tags: %v", err)
		return tagMap
	}

	var tagList struct {
		Value []string `json:"value"`
	}
	json.NewDecoder(resp.Body).Decode(&tagList)
	resp.Body.Close()

	tc.Logger.Printf("Found %d tags", len(tagList.Value))

	// Iterate tags
	for _, tagID := range tagList.Value {
		// Get Tag Details
		resp, err = doReq("GET", fmt.Sprintf("%s/com/vmware/cis/tagging/tag/%s", baseURL, tagID))
		if err != nil {
			continue
		}
		var tagInfo struct {
			Value struct {
				Name       string `json:"name"`
				CategoryID string `json:"category_id"`
			} `json:"value"`
		}
		json.NewDecoder(resp.Body).Decode(&tagInfo)
		resp.Body.Close()

		tagName := tagInfo.Value.Name
		if tagName == "" {
			continue
		}

		// Format: Category:TagName
		fullTagName := tagName
		if catName, ok := catMap[tagInfo.Value.CategoryID]; ok {
			fullTagName = fmt.Sprintf("%s:%s", catName, tagName)
		}

		// Get Attached Objects
		resp, err = doReq("POST", fmt.Sprintf("%s/com/vmware/cis/tagging/tag-association/id:%s?~action=list-attached-objects", baseURL, tagID))
		if err != nil {
			continue
		}

		var attached struct {
			Value []struct {
				ID string `json:"id"` // moid
			} `json:"value"`
		}
		json.NewDecoder(resp.Body).Decode(&attached)
		resp.Body.Close()

		for _, obj := range attached.Value {
			if obj.ID != "" {
				tagMap[obj.ID] = append(tagMap[obj.ID], fullTagName)
			}
		}
	}

	// Debug Logging as requested
	if tc.Config.Debug {
		for moid, tags := range tagMap {
			tc.Debugf("Collected tags for %s: %v", moid, tags)
		}
	}

	return tagMap
}
