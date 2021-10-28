package main

import (
	"bytes"
	"io/ioutil"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/stretchr/testify/assert"
)

const (
	URLAuthenticate              = "/auth"
	URLAuthenticateFailing       = "/auth_fail"
	URLCreateNewApp              = "/new_app"
	URLCreateNewAppFailing       = "/new_app_fail"
	URLCreateNewMeeting          = "/new_meeting"
	URLPerformDiscovery          = "/discovery"
	URLResponseWithAuthHeader    = "/response_with_auth_header"
	URLResponseWithoutAuthHeader = "/response_without_auth_header"
	URLReadUserResource          = "/user"
	URLInvalid                   = "invalid://u r l"
	TestToken                    = "testtoken"
	TestMyOnlineMeetingsURL      = "/ucwa/oauth/v1/applications/123/onlineMeetings/myOnlineMeetings"
	TestOnlineMeetingID          = "FRA03I2T"
	TestJoinURL                  = "https://test.com/testcompany/testuser/FRA03I2T"
	TestUserURL                  = "https://dc2.testcompany.com/Autodiscover/AutodiscoverService.svc/root/oauth/user"
	TestApplicationsURL          = "https://dc2.testcompany.com/ucwa/oauth/v1/applications"
	TestAuthHeader               = "test_auth_header"
)

var (
	server *httptest.Server
)

type LoggerMock struct {
	mock.Mock
}

func (l *LoggerMock) LogError(msg string, keyValuePairs ...interface{}) {}
func (l *LoggerMock) LogWarn(msg string, keyValuePairs ...interface{})  {}
func (l *LoggerMock) LogInfo(msg string, keyValuePairs ...interface{})  {}
func (l *LoggerMock) LogDebug(msg string, keyValuePairs ...interface{}) {}

func TestClient(t *testing.T) {
	setupTestServer(t)
	defer teardown()

	client := NewClient()
	client.setLogger(&LoggerMock{})

	t.Run("test authenticate", func(t *testing.T) {
		r, err := client.authenticate(server.URL+URLAuthenticate, url.Values{})

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TestToken, r.AccessToken)

		r, err = client.authenticate(URLInvalid, url.Values{})

		assert.NotNil(t, err)
		assert.Nil(t, r)

		r, err = client.authenticate(server.URL+URLAuthenticateFailing, url.Values{})

		assert.NotNil(t, err)
		assert.Nil(t, r)
	})

	t.Run("test createNewApplication", func(t *testing.T) {
		r, err := client.createNewApplication(server.URL+URLCreateNewApp, &NewApplicationRequest{}, TestToken)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TestMyOnlineMeetingsURL, r.Embedded.OnlineMeetings.OnlineMeetingsLinks.MyOnlineMeetings.Href)

		r, err = client.createNewApplication(URLInvalid, nil, TestToken)

		assert.NotNil(t, err)
		assert.Nil(t, r)

		r, err = client.createNewApplication("", nil, TestToken)

		assert.NotNil(t, err)
		assert.Equal(t, "", r.Embedded.OnlineMeetings.OnlineMeetingsLinks.MyOnlineMeetings.Href)

		r, err = client.createNewApplication(server.URL+URLCreateNewAppFailing, nil, TestToken)

		assert.NotNil(t, err)
		assert.Equal(t, "", r.Embedded.OnlineMeetings.OnlineMeetingsLinks.MyOnlineMeetings.Href)
	})

	t.Run("test createNewMeeting", func(t *testing.T) {
		r, err := client.createNewMeeting(server.URL+URLCreateNewMeeting, &NewMeetingRequest{}, TestToken)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TestOnlineMeetingID, r.MeetingID)
		assert.Equal(t, TestJoinURL, r.JoinURL)

		r, err = client.createNewMeeting(URLInvalid, math.Inf(1), TestToken)

		assert.NotNil(t, err)
		assert.Nil(t, r)
	})

	t.Run("test performDiscovery", func(t *testing.T) {
		r, err := client.performDiscovery(server.URL + URLPerformDiscovery)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TestUserURL, r.Links.User.Href)

		r, err = client.performDiscovery(URLInvalid)

		assert.NotNil(t, err)
		assert.Nil(t, r)
	})

	t.Run("test performRequestAndGetAuthHeader", func(t *testing.T) {
		r, err := client.performRequestAndGetAuthHeader(server.URL + URLResponseWithAuthHeader)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TestAuthHeader, *r)

		r, err = client.performRequestAndGetAuthHeader(URLInvalid)
		assert.NotNil(t, err)
		assert.Nil(t, r)

		r, err = client.performRequestAndGetAuthHeader("")
		assert.NotNil(t, err)
		assert.Nil(t, r)

		r, err = client.performRequestAndGetAuthHeader(server.URL + URLResponseWithoutAuthHeader)

		assert.NotNil(t, err)
		assert.Equal(t, "response doesn't have WWW-AUTHENTICATE header", err.Error())
		assert.Nil(t, r)
	})

	t.Run("test readUserResource", func(t *testing.T) {
		r, err := client.readUserResource(server.URL+URLReadUserResource, TestToken)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TestApplicationsURL, r.Links.Applications.Href)

		r, err = client.readUserResource(URLInvalid, TestToken)

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

	mux.HandleFunc(URLAuthenticate, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `{"access_token": "`+TestToken+`"}`)
	})

	mux.HandleFunc(URLAuthenticateFailing, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Ms-Diagnostics", "wrong credentials")
		writer.WriteHeader(http.StatusForbidden)
	})

	mux.HandleFunc(URLCreateNewApp, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `
			{
			  "_embedded": {
				"onlineMeetings": {
				  "_links": {
					"myOnlineMeetings": {
					  "href": "`+TestMyOnlineMeetingsURL+`"
					}
				  }
				}
			  }
			}
		`)
	})

	mux.HandleFunc(URLCreateNewAppFailing, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Ms-Diagnostics", "something went wrong")
		writer.WriteHeader(http.StatusInternalServerError)
	})

	mux.HandleFunc(URLCreateNewMeeting, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `
			{
			  "onlineMeetingId": "`+TestOnlineMeetingID+`",
			  "joinUrl": "`+TestJoinURL+`"
			}
		`)
	})

	mux.HandleFunc(URLPerformDiscovery, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `
			{
			  "_links": {
				"user": {
				  "href": "`+TestUserURL+`"
				}
			  }
			}
		`)
	})

	mux.HandleFunc(URLResponseWithAuthHeader, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("WWW-AUTHENTICATE", TestAuthHeader)
		writer.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc(URLResponseWithoutAuthHeader, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc(URLReadUserResource, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `
			{
			  "_links": {
				"applications": {
				  "href": "`+TestApplicationsURL+`",
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
