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
	URL_AUTHENTICATE                 = "/auth"
	URL_AUTHENTICATE_FAILING         = "/auth_fail"
	URL_CREATE_NEW_APP               = "/new_app"
	URL_CREATE_NEW_APP_FAILING       = "/new_app_fail"
	URL_CREATE_NEW_MEETING           = "/new_meeting"
	URL_PERFORM_DISCOVERY            = "/discovery"
	URL_RESPONSE_WITH_AUTH_HEADER    = "/response_with_auth_header"
	URL_RESPONSE_WITHOUT_AUTH_HEADER = "/response_without_auth_header"
	URL_READ_USER_RESOURCE           = "/user"
	URL_INVALID                      = "invalid://u r l"
	TEST_TOKEN                       = "testtoken"
	TEST_MY_ONLINE_MEETINGS_URL      = "/ucwa/oauth/v1/applications/123/onlineMeetings/myOnlineMeetings"
	TEST_ONLINE_MEETING_ID           = "FRA03I2T"
	TEST_JOIN_URL                    = "https://test.com/testcompany/testuser/FRA03I2T"
	TEST_USER_URL                    = "https://dc2.testcompany.com/Autodiscover/AutodiscoverService.svc/root/oauth/user"
	TEST_APPLICATIONS_URL            = "https://dc2.testcompany.com/ucwa/oauth/v1/applications"
	TEST_AUTH_HEADER                 = "test_auth_header"
)

var (
	server *httptest.Server
)

func TestClient(t *testing.T) {
	setupTestServer(t)
	defer teardown()

	client := NewClient()

	t.Run("test authenticate", func(t *testing.T) {

		r, err := client.authenticate(server.URL+URL_AUTHENTICATE, url.Values{})

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TEST_TOKEN, r.Access_token)

		r, err = client.authenticate(URL_INVALID, url.Values{})

		assert.NotNil(t, err)
		assert.Nil(t, r)

		r, err = client.authenticate(server.URL+URL_AUTHENTICATE_FAILING, url.Values{})

		assert.NotNil(t, err)
		assert.Nil(t, r)
	})

	t.Run("test createNewApplication", func(t *testing.T) {

		r, err := client.createNewApplication(server.URL+URL_CREATE_NEW_APP, &NewApplicationRequest{}, TEST_TOKEN)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TEST_MY_ONLINE_MEETINGS_URL, r.Embedded.OnlineMeetings.OnlineMeetingsLinks.MyOnlineMeetings.Href)

		r, err = client.createNewApplication(URL_INVALID, nil, TEST_TOKEN)

		assert.NotNil(t, err)
		assert.Nil(t, r)

		r, err = client.createNewApplication("", nil, TEST_TOKEN)

		assert.NotNil(t, err)
		assert.Equal(t, "", r.Embedded.OnlineMeetings.OnlineMeetingsLinks.MyOnlineMeetings.Href)

		r, err = client.createNewApplication(server.URL+URL_CREATE_NEW_APP_FAILING, nil, TEST_TOKEN)

		assert.NotNil(t, err)
		assert.Equal(t, "", r.Embedded.OnlineMeetings.OnlineMeetingsLinks.MyOnlineMeetings.Href)
	})

	t.Run("test createNewMeeting", func(t *testing.T) {

		r, err := client.createNewMeeting(server.URL+URL_CREATE_NEW_MEETING, &NewMeetingRequest{}, TEST_TOKEN)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TEST_ONLINE_MEETING_ID, r.MeetingId)
		assert.Equal(t, TEST_JOIN_URL, r.JoinUrl)

		r, err = client.createNewMeeting(URL_INVALID, math.Inf(1), TEST_TOKEN)

		assert.NotNil(t, err)
		assert.Nil(t, r)
	})

	t.Run("test performDiscovery", func(t *testing.T) {

		r, err := client.performDiscovery(server.URL + URL_PERFORM_DISCOVERY)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TEST_USER_URL, r.Links.User.Href)

		r, err = client.performDiscovery(URL_INVALID)

		assert.NotNil(t, err)
		assert.Nil(t, r)
	})

	t.Run("test performRequestAndGetAuthHeader", func(t *testing.T) {

		r, err := client.performRequestAndGetAuthHeader(server.URL + URL_RESPONSE_WITH_AUTH_HEADER)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TEST_AUTH_HEADER, *r)

		r, err = client.performRequestAndGetAuthHeader(URL_INVALID)
		assert.NotNil(t, err)
		assert.Nil(t, r)

		r, err = client.performRequestAndGetAuthHeader("")
		assert.NotNil(t, err)
		assert.Nil(t, r)

		r, err = client.performRequestAndGetAuthHeader(server.URL + URL_RESPONSE_WITHOUT_AUTH_HEADER)

		assert.NotNil(t, err)
		assert.Equal(t, "Response doesn't have WWW-AUTHENTICATE header!", err.Error())
		assert.Nil(t, r)
	})

	t.Run("test readUserResource", func(t *testing.T) {

		r, err := client.readUserResource(server.URL+URL_READ_USER_RESOURCE, TEST_TOKEN)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TEST_APPLICATIONS_URL, r.Links.Applications.Href)

		r, err = client.readUserResource(URL_INVALID, TEST_TOKEN)

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

	mux.HandleFunc(URL_AUTHENTICATE, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `{"access_token": "`+TEST_TOKEN+`"}`)
	})

	mux.HandleFunc(URL_AUTHENTICATE_FAILING, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Ms-Diagnostics", "wrong credentials")
		writer.WriteHeader(http.StatusForbidden)
	})

	mux.HandleFunc(URL_CREATE_NEW_APP, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `
			{
			  "_embedded": {
				"onlineMeetings": {
				  "_links": {
					"myOnlineMeetings": {
					  "href": "`+TEST_MY_ONLINE_MEETINGS_URL+`"
					}
				  }
				}
			  }
			}
		`)
	})

	mux.HandleFunc(URL_CREATE_NEW_APP_FAILING, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Ms-Diagnostics", "something went wrong")
		writer.WriteHeader(http.StatusInternalServerError)
	})

	mux.HandleFunc(URL_CREATE_NEW_MEETING, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `
			{
			  "onlineMeetingId": "`+TEST_ONLINE_MEETING_ID+`",
			  "joinUrl": "`+TEST_JOIN_URL+`"
			}
		`)
	})

	mux.HandleFunc(URL_PERFORM_DISCOVERY, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `
			{
			  "_links": {
				"user": {
				  "href": "`+TEST_USER_URL+`"
				}
			  }
			}
		`)
	})

	mux.HandleFunc(URL_RESPONSE_WITH_AUTH_HEADER, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("WWW-AUTHENTICATE", TEST_AUTH_HEADER)
		writer.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc(URL_RESPONSE_WITHOUT_AUTH_HEADER, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc(URL_READ_USER_RESOURCE, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `
			{
			  "_links": {
				"applications": {
				  "href": "`+TEST_APPLICATIONS_URL+`",
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
