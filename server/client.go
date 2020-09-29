package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

// Client is a new HTTP Client to talk to the Skype server
type Client struct {
	httpClient        *http.Client
	logger            ILogger
	shouldLogRequests bool
}

// NewClient returns a new Client
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (c *Client) setLogger(logger ILogger) {
	c.logger = logger
}

func (c *Client) setShouldLogRequests(shouldLogRequests bool) {
	c.shouldLogRequests = shouldLogRequests
}

func (c *Client) authenticate(url string, body url.Values) (*AuthResponse, error) {
	c.logger.LogInfo("Request in authenticate", "url", url, "body", body)
	resp, err := c.httpClient.PostForm(url, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err = c.validateResponse(resp); err != nil {
		return nil, err
	}

	var authResponse AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&authResponse)
	return &authResponse, err
}

func (c *Client) createNewApplication(url string, body interface{}, token string) (*NewApplicationResponse, error) {
	req, err := c.newRequest("POST", url, body, &token)
	if err != nil {
		return nil, err
	}
	c.logRequest("createNewApplication", req, true)
	var newApplicationResponse NewApplicationResponse
	_, err = c.do(req, &newApplicationResponse)
	return &newApplicationResponse, err
}

func (c *Client) createNewMeeting(url string, body interface{}, token string) (*NewMeetingResponse, error) {
	req, err := c.newRequest("POST", url, body, &token)
	if err != nil {
		return nil, err
	}
	c.logRequest("createNewMeeting", req, true)
	var newMeetingResponse NewMeetingResponse
	_, err = c.do(req, &newMeetingResponse)
	return &newMeetingResponse, err
}

func (c *Client) performDiscovery(url string) (*DiscoveryResponse, error) {
	req, err := c.newRequest("GET", url, nil, nil)
	if err != nil {
		return nil, err
	}
	c.logRequest("performDiscovery", req, false)
	var discoveryResponse DiscoveryResponse
	_, err = c.do(req, &discoveryResponse)
	return &discoveryResponse, err
}

func (c *Client) readUserResource(url string, token string) (*UserResourceResponse, error) {
	req, err := c.newRequest("GET", url, nil, &token)
	if err != nil {
		return nil, err
	}
	c.logRequest("readUserResource", req, false)
	var userResourceResponse UserResourceResponse
	_, err = c.do(req, &userResourceResponse)
	return &userResourceResponse, err
}

func (c *Client) newRequest(method, url string, body interface{}, token *string) (*http.Request, error) {
	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != nil {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	req.Header.Set("Accept", "application/json")

	return req, nil
}

func (c *Client) performRequestAndGetAuthHeader(url string) (*string, error) {
	req, err := c.newRequest("GET", url, nil, nil)
	if err != nil {
		return nil, err
	}
	c.logRequest("performRequestAndGetAuthHeader", req, false)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	for k, v := range resp.Header {
		if strings.ToUpper(k) == "WWW-AUTHENTICATE" {
			authHeader := strings.Join(v, ",")
			return &authHeader, nil
		}
	}

	return nil, errors.New("response doesn't have WWW-AUTHENTICATE header")
}

func (c *Client) do(req *http.Request, v interface{}) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err = c.validateResponse(resp); err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(v)
	return resp, err
}

func (c *Client) validateResponse(resp *http.Response) error {
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		msg := "Bad response received. Status: " + resp.Status + ". "

		xmd := resp.Header.Get("X-Ms-Diagnostics")
		if xmd != "" {
			msg += "X-Ms-Diagnostics from response: " + xmd + ". "
		} else {
			msg += "Doesn't have X-Ms-Diagnostics header. "
		}

		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		if len(bodyBytes) > 0 {
			msg += "Response body: " + string(bodyBytes) + ". "
		} else {
			msg += "Doesn't have body. "
		}

		return errors.New(msg)
	}

	return nil
}

func (c *Client) logRequest(methodName string, r *http.Request, hasBody bool) {
	if c.shouldLogRequests {
		requestDump, _ := httputil.DumpRequest(r, hasBody)
		c.logger.LogInfo("Request in "+methodName, "request", string(requestDump))
	}
}
