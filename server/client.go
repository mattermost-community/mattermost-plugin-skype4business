package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	httpClient *http.Client
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (c *Client) authenticate(url string, body url.Values) (*AuthResponse, error) {
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
	var newApplicationResponse NewApplicationResponse
	_, err = c.do(req, &newApplicationResponse)
	return &newApplicationResponse, err
}

func (c *Client) createNewMeeting(url string, body interface{}, token string) (*NewMeetingResponse, error) {
	req, err := c.newRequest("POST", url, body, &token)
	if err != nil {
		return nil, err
	}
	var newMeetingResponse NewMeetingResponse
	_, err = c.do(req, &newMeetingResponse)
	return &newMeetingResponse, err
}

func (c *Client) performDiscovery(url string) (*DiscoveryResponse, error) {
	req, err := c.newRequest("GET", url, nil, nil)
	if err != nil {
		return nil, err
	}
	var discoveryResponse DiscoveryResponse
	_, err = c.do(req, &discoveryResponse)
	return &discoveryResponse, err
}

func (c *Client) readUserResource(url string, token string) (*UserResourceResponse, error) {
	req, err := c.newRequest("GET", url, nil, &token)
	if err != nil {
		return nil, err
	}
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

	return nil, errors.New("Response doesn't have WWW-AUTHENTICATE header!")
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
		if bodyBytes != nil && len(bodyBytes) > 0 {
			msg += "Response body: " + string(bodyBytes) + ". "
		} else {
			msg += "Doesn't have body. "
		}

		return errors.New(msg)
	}

	return nil
}
