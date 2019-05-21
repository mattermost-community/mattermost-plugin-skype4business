package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mattermost/mattermost-server/model"
	"github.com/mattermost/mattermost-server/plugin"
	"github.com/mattermost/mattermost-server/plugin/plugintest"
	"github.com/mattermost/mattermost-server/plugin/plugintest/mock"
	"github.com/stretchr/testify/assert"
)

func TestPlugin(t *testing.T) {

	validMeetingRequest := httptest.NewRequest("POST", "/api/v1/register_meeting_from_online_version", strings.NewReader("{\"channel_id\": \"thechannelid\", \"meeting_id\": \"L30IC51J\"}"))
	validMeetingRequest.Header.Add("Mattermost-User-Id", "theuserid")

	validClientIdRequest := httptest.NewRequest("GET", "/api/v1/client_id", nil)
	validClientIdRequest.Header.Add("Mattermost-User-Id", "theuserid")

	noAuthClientIdRequest := httptest.NewRequest("GET", "/api/v1/client_id", nil)

	validProductTypeReqeust := httptest.NewRequest("GET", "/api/v1/product_type", nil)
	validProductTypeReqeust.Header.Add("Mattermost-User-Id", "theuserid")

	noAuthProductTypeReqeust := httptest.NewRequest("GET", "/api/v1/product_type", nil)

	validAuthorizeInADDRequest := httptest.NewRequest("GET", "/api/v1/auth?mattermost_user_id=theuserid&navigateTo=https%3A%2F%2Fwww.test.com%2F%3Fresponse_type%3Did_token%26state%3D123", nil)

	invalidAuthorizeInADDRequest1 := httptest.NewRequest("GET", "/api/v1/auth?navigateTo=https%3A%2F%2Fwww.test.com%2F%3Fresponse_type%3Did_token%26state%3D123", nil)
	invalidAuthorizeInADDRequest2 := httptest.NewRequest("GET", "/api/v1/auth?mattermost_user_id=theuserid", nil)
	invalidAuthorizeInADDRequest3 := httptest.NewRequest("GET", "/api/v1/auth?mattermost_user_id=theuserid&navigateTo=https%3A%2F%2Fwww.test.com%2F%3Fresponse_type%3Did_token", nil)

	validCompleteAuthorizeInAddRequest := httptest.NewRequest("POST", "/api/v1/auth_redirect", strings.NewReader("id_token=321&state=123"))
	validCompleteAuthorizeInAddRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	invalidCompleteAuthorizeInAddRequest1 := httptest.NewRequest("POST", "/api/v1/auth_redirect", strings.NewReader("id_token=321"))
	invalidCompleteAuthorizeInAddRequest1.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	invalidCompleteAuthorizeInAddRequest2 := httptest.NewRequest("POST", "/api/v1/auth_redirect", strings.NewReader("state=123"))
	invalidCompleteAuthorizeInAddRequest2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	invalidCompleteAuthorizeInAddRequest3 := httptest.NewRequest("POST", "/api/v1/auth_redirect", strings.NewReader("state=123"))

	noAuthMeetingRequest := httptest.NewRequest("POST", "/api/v1/register_meeting_from_online_version", strings.NewReader("{\"channel_id\": \"thechannelid\"}"))

	for name, tc := range map[string]struct {
		Request            *http.Request
		CreatePostError    *model.AppError
		ExpectedStatusCode int
	}{
		"UnauthorizedMeetingRequest": {
			Request:            noAuthMeetingRequest,
			ExpectedStatusCode: http.StatusUnauthorized,
		},
		"ValidMeetingRequest": {
			Request:            validMeetingRequest,
			ExpectedStatusCode: http.StatusOK,
		},
		"ValidClientIdRequest": {
			Request:            validClientIdRequest,
			ExpectedStatusCode: http.StatusOK,
		},
		"UnauthorizedClientIdRequest": {
			Request:            noAuthClientIdRequest,
			ExpectedStatusCode: http.StatusUnauthorized,
		},
		"ValidProductTypeReqeust": {
			Request:            validProductTypeReqeust,
			ExpectedStatusCode: http.StatusOK,
		},
		"UnauthorizedProductTypeRequest": {
			Request:            noAuthProductTypeReqeust,
			ExpectedStatusCode: http.StatusUnauthorized,
		},
		"ValidAuthorizeInADDRequest": {
			Request:            validAuthorizeInADDRequest,
			ExpectedStatusCode: http.StatusFound,
		},
		"InvalidAuthorizeInADDRequest1": {
			Request:            invalidAuthorizeInADDRequest1,
			ExpectedStatusCode: http.StatusUnauthorized,
		},
		"InvalidAuthorizeInADDRequest2": {
			Request:            invalidAuthorizeInADDRequest2,
			ExpectedStatusCode: http.StatusBadRequest,
		},
		"InvalidAuthorizeInADDRequest3": {
			Request:            invalidAuthorizeInADDRequest3,
			ExpectedStatusCode: http.StatusBadRequest,
		},
		"ValidCompleteAuthorizeInAddRequest": {
			Request:            validCompleteAuthorizeInAddRequest,
			ExpectedStatusCode: http.StatusOK,
		},
		"InvalidCompleteAuthorizeInAddRequest1": {
			Request:            invalidCompleteAuthorizeInAddRequest1,
			ExpectedStatusCode: http.StatusBadRequest,
		},
		"InvalidCompleteAuthorizeInAddRequest2": {
			Request:            invalidCompleteAuthorizeInAddRequest2,
			ExpectedStatusCode: http.StatusBadRequest,
		},
		"InvalidCompleteAuthorizeInAddRequest3": {
			Request:            invalidCompleteAuthorizeInAddRequest3,
			ExpectedStatusCode: http.StatusBadRequest,
		},
	} {
		t.Run(name, func(t *testing.T) {
			api := &plugintest.API{}

			api.On("GetUser", "theuserid").Return(&model.User{
				Id:    "theuserid",
				Email: "theuseremail",
			}, (*model.AppError)(nil))

			api.On("GetChannelMember", "thechannelid", "theuserid").Return(&model.ChannelMember{}, (*model.AppError)(nil))
			api.On("CreatePost", mock.AnythingOfType("*model.Post")).Return(&model.Post{}, (*model.AppError)(nil))
			api.On("KVSet", fmt.Sprintf("%v%v", POST_MEETING_KEY, "L30IC51J"), mock.AnythingOfType("[]uint8")).Return((*model.AppError)(nil))
			api.On("KVSet", "123", []byte("theuserid")).Return((*model.AppError)(nil))
			api.On("KVGet", "123").Return([]byte("theuserid"), (*model.AppError)(nil))
			api.On("KVDelete", "123").Return((*model.AppError)(nil))
			api.On("PublishWebSocketEvent", "authenticated", mock.Anything, mock.Anything).Return()

			p := Plugin{}
			p.setConfiguration(&configuration{
				ClientId:    "123123123",
				ProductType: PRODUCT_TYPE_ONLINE,
			})
			p.SetAPI(api)
			err := p.OnActivate()
			assert.Nil(t, err)

			w := httptest.NewRecorder()
			p.ServeHTTP(&plugin.Context{}, w, tc.Request)
			assert.Equal(t, tc.ExpectedStatusCode, w.Result().StatusCode)
		})
	}

	t.Run("create_meeting_in_server_version", func(t *testing.T) {

		givenDomainUrl := "domain.test"
		expectedDiscoveryUrl := "https://lyncdiscover.domain.test"
		expectedUserResourceUrl := "https://win-123.domain.test/Autodiscover/AutodiscoverService.svc/root/oauth/user"
		expectedApplicationsUrl := "https://win-123.domain.test/ucwa/oauth/v1/applications"
		expectedMeetingsUrl := "/ucwa/oauth/v1/applications/432/onlineMeetings/myOnlineMeetings"
		expectedToken := "123"
		expectedMeetingId := "BR140MRA"

		api := &plugintest.API{}
		api.On("GetUser", "theuserid").Return(&model.User{
			Id:    "theuserid",
			Email: "theuseremail",
		}, (*model.AppError)(nil))
		api.On("GetChannelMember", "thechannelid", "theuserid").Return(&model.ChannelMember{}, (*model.AppError)(nil))
		api.On("CreatePost", mock.AnythingOfType("*model.Post")).Return(&model.Post{}, (*model.AppError)(nil))
		api.On("KVSet", fmt.Sprintf("%v%v", POST_MEETING_KEY, expectedMeetingId), mock.AnythingOfType("[]uint8")).Return((*model.AppError)(nil))

		clientMock := &ClientMock{}
		clientMock.On("performDiscovery", expectedDiscoveryUrl).Return(&DiscoveryResponse{
			Links: Links{
				User: Href{Href: expectedUserResourceUrl},
			},
		}, nil)
		clientMock.On("authenticate", mock.Anything, mock.Anything).Return(&AuthResponse{
			Access_token: expectedToken,
		}, nil)
		clientMock.On("readUserResource", expectedUserResourceUrl, mock.Anything).Return(&UserResourceResponse{
			Links: Links{
				Applications: Href{Href: expectedApplicationsUrl},
				Redirect:     Href{},
			},
		}, nil)
		clientMock.On("createNewApplication", expectedApplicationsUrl, mock.Anything, expectedToken).Return(&NewApplicationResponse{
			Embedded: Embedded{
				OnlineMeetings: OnlineMeetings{
					OnlineMeetingsLinks: OnlineMeetingsLinks{
						MyOnlineMeetings: Href{Href: expectedMeetingsUrl},
					},
				},
			},
		}, nil)
		clientMock.On("createNewMeeting", mock.Anything, mock.Anything, mock.Anything).Return(&NewMeetingResponse{
			MeetingId: expectedMeetingId,
		}, nil)

		p := Plugin{client: clientMock}
		p.setConfiguration(&configuration{
			Domain:      givenDomainUrl,
			Username:    "username",
			Password:    "password",
			ProductType: PRODUCT_TYPE_SERVER,
		})
		p.SetAPI(api)
		err := p.OnActivate()
		assert.Nil(t, err)

		r := httptest.NewRequest("POST", "/api/v1/create_meeting_in_server_version", strings.NewReader("{\"channel_id\": \"thechannelid\", \"personal\": true}"))
		r.Header.Add("Mattermost-User-Id", "theuserid")
		w := httptest.NewRecorder()
		p.ServeHTTP(&plugin.Context{}, w, r)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	})
}

type ClientMock struct {
	mock.Mock
}

func (c *ClientMock) authenticate(url string, body url.Values) (*AuthResponse, error) {
	ret := c.Called(url, body)

	if ret.Get(0) != nil && ret.Get(1) == nil {
		return ret.Get(0).(*AuthResponse), nil
	} else {
		return nil, ret.Error(1)
	}
}

func (c *ClientMock) createNewApplication(url string, body interface{}, token string) (*NewApplicationResponse, error) {
	ret := c.Called(url, body, token)

	if ret.Get(0) != nil && ret.Get(1) == nil {
		return ret.Get(0).(*NewApplicationResponse), nil
	} else {
		return nil, ret.Error(1)
	}
}

func (c *ClientMock) createNewMeeting(url string, body interface{}, token string) (*NewMeetingResponse, error) {
	ret := c.Called(url, body, token)

	if ret.Get(0) != nil && ret.Get(1) == nil {
		return ret.Get(0).(*NewMeetingResponse), nil
	} else {
		return nil, ret.Error(1)
	}
}

func (c *ClientMock) performDiscovery(url string) (*DiscoveryResponse, error) {
	ret := c.Called(url)

	if ret.Get(0) != nil && ret.Get(1) == nil {
		return ret.Get(0).(*DiscoveryResponse), nil
	} else {
		return nil, ret.Error(1)
	}
}

func (c *ClientMock) readUserResource(url string, token string) (*UserResourceResponse, error) {
	ret := c.Called(url, token)

	if ret.Get(0) != nil && ret.Get(1) == nil {
		return ret.Get(0).(*UserResourceResponse), nil
	} else {
		return nil, ret.Error(1)
	}
}
