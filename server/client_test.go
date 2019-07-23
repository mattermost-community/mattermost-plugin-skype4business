package main

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

const (
	UrlAuthenticate              = "/auth"
	UrlAuthenticateFailing       = "/auth_fail"
	UrlCreateNewApp              = "/new_app"
	UrlCreateNewAppFailing       = "/new_app_fail"
	UrlCreateNewMeeting          = "/new_meeting"
	UrlPerformDiscovery          = "/discovery"
	UrlResponseWithAuthHeader    = "/response_with_auth_header"
	UrlResponseWithoutAuthHeader = "/response_without_auth_header"
	UrlReadUserResource          = "/user"
	UrlInvalid              = "invalid://u r l"
	TestToken               = "testtoken"
	TestMyOnlineMeetingsUrl = "/ucwa/oauth/v1/applications/123/onlineMeetings/myOnlineMeetings"
	TestOnlineMeetingId     = "FRA03I2T"
	TestJoinUrl             = "https://test.com/testcompany/testuser/FRA03I2T"
	TestUserUrl             = "https://dc2.testcompany.com/Autodiscover/AutodiscoverService.svc/root/oauth/user"
	TestApplicationsUrl     = "https://dc2.testcompany.com/ucwa/oauth/v1/applications"
	TestAuthHeader          = "test_auth_header"
)

var (
	server *httptest.Server
)

func TestClient(t *testing.T) {
	setupTestServer(t)
	defer teardown()

	client := NewClient()

	t.Run("test authenticate", func(t *testing.T) {

		r, err := client.authenticate(server.URL+UrlAuthenticate, url.Values{})

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TestToken, r.Access_token)

		r, err = client.authenticate(UrlInvalid, url.Values{})

		assert.NotNil(t, err)
		assert.Nil(t, r)

		r, err = client.authenticate(server.URL+UrlAuthenticateFailing, url.Values{})

		assert.NotNil(t, err)
		assert.Nil(t, r)
	})

	t.Run("test createNewApplication", func(t *testing.T) {

		r, err := client.createNewApplication(server.URL+UrlCreateNewApp, &NewApplicationRequest{}, TestToken)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TestMyOnlineMeetingsUrl, r.Embedded.OnlineMeetings.OnlineMeetingsLinks.MyOnlineMeetings.Href)

		r, err = client.createNewApplication(UrlInvalid, nil, TestToken)

		assert.NotNil(t, err)
		assert.Nil(t, r)

		r, err = client.createNewApplication("", nil, TestToken)

		assert.NotNil(t, err)
		assert.Equal(t, "", r.Embedded.OnlineMeetings.OnlineMeetingsLinks.MyOnlineMeetings.Href)

		r, err = client.createNewApplication(server.URL+UrlCreateNewAppFailing, nil, TestToken)

		assert.NotNil(t, err)
		assert.Equal(t, "", r.Embedded.OnlineMeetings.OnlineMeetingsLinks.MyOnlineMeetings.Href)
	})

	t.Run("test createNewMeeting", func(t *testing.T) {

		r, err := client.createNewMeeting(server.URL+UrlCreateNewMeeting, &NewMeetingRequest{}, TestToken)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TestOnlineMeetingId, r.MeetingId)
		assert.Equal(t, TestJoinUrl, r.JoinUrl)

		r, err = client.createNewMeeting(UrlInvalid, math.Inf(1), TestToken)

		assert.NotNil(t, err)
		assert.Nil(t, r)
	})

	t.Run("test performDiscovery", func(t *testing.T) {

		r, err := client.performDiscovery(server.URL + UrlPerformDiscovery)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TestUserUrl, r.Links.User.Href)

		r, err = client.performDiscovery(UrlInvalid)

		assert.NotNil(t, err)
		assert.Nil(t, r)
	})

	t.Run("test performRequestAndGetAuthHeader", func(t *testing.T) {

		r, err := client.performRequestAndGetAuthHeader(server.URL + UrlResponseWithAuthHeader)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TestAuthHeader, *r)

		r, err = client.performRequestAndGetAuthHeader(UrlInvalid)
		assert.NotNil(t, err)
		assert.Nil(t, r)

		r, err = client.performRequestAndGetAuthHeader("")
		assert.NotNil(t, err)
		assert.Nil(t, r)

		r, err = client.performRequestAndGetAuthHeader(server.URL + UrlResponseWithoutAuthHeader)

		assert.NotNil(t, err)
		assert.Equal(t, "Response doesn't have WWW-AUTHENTICATE header!", err.Error())
		assert.Nil(t, r)
	})

	t.Run("test readUserResource", func(t *testing.T) {

		r, err := client.readUserResource(server.URL+UrlReadUserResource, TestToken)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TestApplicationsUrl, r.Links.Applications.Href)

		r, err = client.readUserResource(UrlInvalid, TestToken)

		assert.NotNil(t, err)
		assert.Nil(t, r)
	})

	t.Run("test validateResponse", func(t *testing.T) {

		resp := &http.Response{
			StatusCode: http.StatusOK,
		}

		err := client.validateResponse(resp)

		assert.NoError(t, err)

		resp = &http.Response{
			StatusCode: http.StatusCreated,
		}

		err = client.validateResponse(resp)

		assert.NoError(t, err)

		resp = &http.Response{
			Status:     strconv.Itoa(http.StatusInternalServerError) + " " + http.StatusText(http.StatusInternalServerError),
			StatusCode: http.StatusInternalServerError,
			Body:       ioutil.NopCloser(bytes.NewBufferString("test body")),
		}

		err = client.validateResponse(resp)

		assert.Equal(
			t,
			"Bad response received. Status: 500 Internal Server Error. Doesn't have X-Ms-Diagnostics header. "+
				"Response body: test body. ",
			err.Error())

		resp = &http.Response{
			Status:     strconv.Itoa(http.StatusInternalServerError) + " " + http.StatusText(http.StatusInternalServerError),
			StatusCode: http.StatusInternalServerError,
			Body:       ioutil.NopCloser(bytes.NewBufferString("")),
		}

		err = client.validateResponse(resp)

		assert.Equal(
			t,
			"Bad response received. Status: 500 Internal Server Error. Doesn't have X-Ms-Diagnostics header. "+
				"Doesn't have body. ",
			err.Error())
	})
}

func setupTestServer(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc(UrlAuthenticate, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `{"access_token": "`+TestToken+`"}`)
	})

	mux.HandleFunc(UrlAuthenticateFailing, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Ms-Diagnostics", "wrong credentials")
		writer.WriteHeader(http.StatusForbidden)
	})

	mux.HandleFunc(UrlCreateNewApp, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `
			{
			  "_embedded": {
				"onlineMeetings": {
				  "_links": {
					"myOnlineMeetings": {
					  "href": "`+TestMyOnlineMeetingsUrl+`"
					}
				  }
				}
			  }
			}
		`)
	})

	mux.HandleFunc(UrlCreateNewAppFailing, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Ms-Diagnostics", "something went wrong")
		writer.WriteHeader(http.StatusInternalServerError)
	})

	mux.HandleFunc(UrlCreateNewMeeting, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `
			{
			  "onlineMeetingId": "`+TestOnlineMeetingId+`",
			  "joinUrl": "`+TestJoinUrl+`"
			}
		`)
	})

	mux.HandleFunc(UrlPerformDiscovery, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `
			{
			  "_links": {
				"user": {
				  "href": "`+TestUserUrl+`"
				}
			  }
			}
		`)
	})

	mux.HandleFunc(UrlResponseWithAuthHeader, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("WWW-AUTHENTICATE", TestAuthHeader)
		writer.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc(UrlResponseWithoutAuthHeader, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc(UrlReadUserResource, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `
			{
			  "_links": {
				"applications": {
				  "href": "`+TestApplicationsUrl+`",
				  "revision": "2"
				}
			  }
			}
		`)
	})

	apiHandler := http.NewServeMux()
	apiHandler.Handle("/", mux)

	server = httptest.NewServer(apiHandler)
}

func writeResponse(t *testing.T, writer http.ResponseWriter, response string) {
	writer.WriteHeader(http.StatusOK)
	_, err := writer.Write([]byte(response))
	if err != nil {
		t.Fatal(err)
	}
}

func teardown() {
	server.Close()
}
