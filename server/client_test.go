package main

import (
	"github.com/stretchr/testify/assert"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

const (
	URL_AUTHENTICATE            = "/auth"
	URL_CREATE_NEW_APP          = "/new_app"
	URL_CREATE_NEW_MEETING      = "/new_meeting"
	URL_PERFORM_DISCOVERY       = "/discovery"
	URL_READ_USER_RESOURCE      = "/user"
	URL_INVALID                 = "invalid://u r l"
	TEST_TOKEN                  = "testtoken"
	TEST_MY_ONLINE_MEETINGS_URL = "/ucwa/oauth/v1/applications/123/onlineMeetings/myOnlineMeetings"
	TEST_ONLINE_MEETING_ID      = "FRA03I2T"
	TEST_JOIN_URL               = "https://test.com/testcompany/testuser/FRA03I2T"
	TEST_USER_URL               = "https://dc2.testcompany.com/Autodiscover/AutodiscoverService.svc/root/oauth/user"
	TEST_APPLICATIONS_URL       = "https://dc2.testcompany.com/ucwa/oauth/v1/applications"
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

	t.Run("test readUserResource", func(t *testing.T) {

		r, err := client.readUserResource(server.URL+URL_READ_USER_RESOURCE, TEST_TOKEN)

		assert.Nil(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, TEST_APPLICATIONS_URL, r.Links.Applications.Href)

		r, err = client.readUserResource(URL_INVALID, TEST_TOKEN)

		assert.NotNil(t, err)
		assert.Nil(t, r)
	})
}

func setupTestServer(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc(URL_AUTHENTICATE, func(writer http.ResponseWriter, request *http.Request) {
		writeResponse(t, writer, `{"access_token": "`+TEST_TOKEN+`"}`)
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
