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

			siteUrl := "https://domain.test"
			api.On("GetConfig").Return(&model.Config{
				ServiceSettings: model.ServiceSettings{
					SiteURL: &siteUrl,
				},
			})

			api.On("GetChannelMember", "thechannelid", "theuserid").Return(&model.ChannelMember{}, (*model.AppError)(nil))
			api.On("CreatePost", mock.AnythingOfType("*model.Post")).Return(&model.Post{}, (*model.AppError)(nil))
			api.On("KVSet", fmt.Sprintf("%v%v", PostMeetingKey, "L30IC51J"), mock.AnythingOfType("[]uint8")).Return((*model.AppError)(nil))
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

		mmChannelId := "234"
		mmUser := model.User{Id: "userNo123", Email: "user123@test.com", Username: "testusername"}
		w := httptest.NewRecorder()

		t.Run("single_domain_scenario", func(t *testing.T) {
			mocks := makeMocks(mmChannelId, mmUser, false)

			mocks.Plugin.ServeHTTP(&plugin.Context{}, w, makeCreateMeetingInServerVersionRequest(mmChannelId, mmUser))
			assert.Equal(t, http.StatusOK, w.Result().StatusCode)

			verifyMocksCalls(t, mocks, false)
		})

		t.Run("create_meeting_in_server_version_split_domain_scenario", func(t *testing.T) {
			mocks := makeMocks(mmChannelId, mmUser, true)

			mocks.Plugin.ServeHTTP(&plugin.Context{}, w, makeCreateMeetingInServerVersionRequest(mmChannelId, mmUser))
			assert.Equal(t, http.StatusOK, w.Result().StatusCode)

			verifyMocksCalls(t, mocks, true)
		})
	})
}

func makeMocks(mmChannelId string, mmUser model.User, splitDomain bool) Mocks {
	firstDomain := "firstdomain.com"
	secondDomain := "seconddomain.com"
	pluginConfigToReturn := configuration{
		Domain:      firstDomain,
		Username:    "simpleusername",
		Password:    "veryhardpassword",
		ProductType: PRODUCT_TYPE_SERVER,
	}

	tokenToReturnForFirstDomain := "tokenNo1"
	expectedTokenUrlForFirstDomain := makeTokenUrl(firstDomain)
	authHeaderToReturnForFirstDomain := makeAuthHeader(expectedTokenUrlForFirstDomain)
	expectedUrlValuesForFirstDomain := makeUrlValues(pluginConfigToReturn, firstDomain)

	var (
		tokenToReturnForSecondDomain                 = ""
		expectedTokenUrlForSecondDomain              = ""
		authHeaderToReturnForSecondDomain            = ""
		expectedUrlValuesForSecondDomain  url.Values = nil
	)
	if splitDomain {
		tokenToReturnForSecondDomain = "tokenNo2"
		expectedTokenUrlForSecondDomain = makeTokenUrl(secondDomain)
		authHeaderToReturnForSecondDomain = makeAuthHeader(expectedTokenUrlForSecondDomain)
		expectedUrlValuesForSecondDomain = makeUrlValues(pluginConfigToReturn, secondDomain)
	}

	expectedApplicationsUrl := makeApplicationsUrl(firstDomain)
	if splitDomain {
		expectedApplicationsUrl = makeApplicationsUrl(secondDomain)
	}

	expectedUserResourceUrl := makeUserUrl(firstDomain)
	expectedMeetingsUrl := "/ucwa/oauth/v1/applications/432/onlineMeetings/myOnlineMeetings"
	expectedMeetingId := "BR140MRA"
	expectedNewApplicationRequest := makeNewApplicationRequest()
	serverConfigToReturn := makeServerConfiguration(&firstDomain)
	expectedPostMeetingId := "post_meeting_" + expectedMeetingId
	discoveryUrlToReturn := "https://lyncdiscover." + firstDomain
	discoveryResponseToReturn := makeDiscoveryResponse(expectedUserResourceUrl)
	userResourceResponseToReturn := makeUserResourceResponse(expectedApplicationsUrl)
	newApplicationResponseToReturn := makeNewApplicationResponse(expectedMeetingsUrl)
	expectedNewMeetingRequest := makeNewMeetingRequest(mmUser)

	expectedFullMeetingUrl := makeMeetingUrl(firstDomain, expectedMeetingsUrl)
	newMeetingResponseToReturn := makeNewMeetingResponse(expectedMeetingId, firstDomain)
	if splitDomain {
		expectedFullMeetingUrl = makeMeetingUrl(secondDomain, expectedMeetingsUrl)
		newMeetingResponseToReturn = makeNewMeetingResponse(expectedMeetingId, secondDomain)
	}

	expectedPost := makePost(mmUser, mmChannelId, newMeetingResponseToReturn, pluginConfigToReturn)

	api := plugintest.API{}
	api.On("GetConfig").Return(serverConfigToReturn).Times(1)
	api.On("GetUser", mmUser.Id).Return(&mmUser, (*model.AppError)(nil)).Times(1)
	api.On("GetChannelMember", mmChannelId, mmUser.Id).
		Return(&model.ChannelMember{}, (*model.AppError)(nil)).Times(1)
	api.On("KVGet", RootUrlKey).
		Return([]byte(discoveryUrlToReturn), (*model.AppError)(nil)).Times(1)
	api.On("CreatePost", expectedPost).
		Return(&model.Post{}, (*model.AppError)(nil)).Times(1)
	api.On("KVSet", expectedPostMeetingId, mock.AnythingOfType("[]uint8")).
		Return((*model.AppError)(nil)).Times(1)

	clientMock := ClientMock{}
	clientMock.On("performDiscovery", "https://lyncdiscover."+firstDomain).
		Return(discoveryResponseToReturn, nil).Times(1)
	clientMock.On("performRequestAndGetAuthHeader", expectedUserResourceUrl).
		Return(&authHeaderToReturnForFirstDomain, nil).Times(1)
	clientMock.On("authenticate", expectedTokenUrlForFirstDomain, expectedUrlValuesForFirstDomain).
		Return(&AuthResponse{Access_token: tokenToReturnForFirstDomain}, nil).Times(1)

	tokenToBeUsed := tokenToReturnForFirstDomain
	if splitDomain {
		clientMock.On("authenticate", expectedTokenUrlForSecondDomain, expectedUrlValuesForSecondDomain).
			Return(&AuthResponse{Access_token: tokenToReturnForSecondDomain}, nil).Times(1)
		clientMock.On("performRequestAndGetAuthHeader", expectedApplicationsUrl).
			Return(&authHeaderToReturnForSecondDomain, nil).Times(1)
		tokenToBeUsed = tokenToReturnForSecondDomain
	}

	clientMock.On("readUserResource", expectedUserResourceUrl, tokenToReturnForFirstDomain).
		Return(userResourceResponseToReturn, nil).Times(1)
	clientMock.On(
		"createNewApplication",
		expectedApplicationsUrl,
		expectedNewApplicationRequest,
		tokenToBeUsed,
	).Return(newApplicationResponseToReturn, nil).Times(1)
	clientMock.On(
		"createNewMeeting",
		expectedFullMeetingUrl,
		expectedNewMeetingRequest,
		tokenToBeUsed,
	).Return(&newMeetingResponseToReturn, nil).Times(1)

	p := Plugin{client: &clientMock}
	p.SetAPI(&api)
	p.setConfiguration(&pluginConfigToReturn)

	return Mocks{
		Api:    &api,
		Client: &clientMock,
		Plugin: &p,
	}
}

func verifyMocksCalls(t *testing.T, mocks Mocks, splitDomain bool) {
	mocks.Api.AssertNumberOfCalls(t, "GetConfig", 1)
	mocks.Api.AssertNumberOfCalls(t, "GetUser", 1)
	mocks.Api.AssertNumberOfCalls(t, "GetChannelMember", 1)
	mocks.Api.AssertNumberOfCalls(t, "KVGet", 1)
	mocks.Api.AssertNumberOfCalls(t, "CreatePost", 1)
	mocks.Api.AssertNumberOfCalls(t, "KVSet", 1)

	mocks.Client.AssertNumberOfCalls(t, "performDiscovery", 1)
	mocks.Client.AssertNumberOfCalls(t, "readUserResource", 1)
	mocks.Client.AssertNumberOfCalls(t, "createNewApplication", 1)
	mocks.Client.AssertNumberOfCalls(t, "createNewMeeting", 1)
	if splitDomain {
		mocks.Client.AssertNumberOfCalls(t, "performRequestAndGetAuthHeader", 2)
		mocks.Client.AssertNumberOfCalls(t, "authenticate", 2)
	} else {
		mocks.Client.AssertNumberOfCalls(t, "performRequestAndGetAuthHeader", 1)
		mocks.Client.AssertNumberOfCalls(t, "authenticate", 1)
	}
}

type Mocks struct {
	Api    *plugintest.API
	Client *ClientMock
	Plugin *Plugin
}

func makeCreateMeetingInServerVersionRequest(mmChannelId string, mmUser model.User) *http.Request {
	r := httptest.NewRequest("POST", "/api/v1/create_meeting_in_server_version",
		strings.NewReader("{\"channel_id\": \""+mmChannelId+"\", \"personal\": true}"))
	r.Header.Add("Mattermost-User-Id", mmUser.Id)
	return r
}

func makeServerConfiguration(siteUrl *string) *model.Config {
	return &model.Config{
		ServiceSettings: model.ServiceSettings{
			SiteURL: siteUrl,
		},
	}
}

func makeDiscoveryResponse(userUrl string) *DiscoveryResponse {
	return &DiscoveryResponse{
		Links: Links{
			User: Href{Href: userUrl},
		},
	}
}

func makeUserUrl(domain string) string {
	return "https://" + domain + "/Autodiscover/AutodiscoverService.svc/root/oauth/user"
}

func makeUserResourceResponse(applicationsUrl string) *UserResourceResponse {
	return &UserResourceResponse{
		Links: Links{
			Applications: Href{Href: applicationsUrl},
			Redirect:     Href{},
		},
	}
}

func makeTokenUrl(domain string) string {
	return "https://" + domain + "/WebTicket/oauthtoken"
}

func makeAuthHeader(tokenUrl string) string {
	return "WWW-Authenticate: MsRtcOAuth href=" + tokenUrl +
		",grant_type=\"urn:microsoft.rtc:windows,urn:microsoft.rtc:anonmeeting,password\""
}

func makeUrlValues(pluginConfig configuration, domain string) url.Values {
	return url.Values{
		"grant_type": []string{"password"},
		"password":   []string{pluginConfig.Password},
		"resource":   []string{domain},
		"username":   []string{pluginConfig.Username},
	}
}

func makeApplicationsUrl(domain string) string {
	return "https://" + domain + "/ucwa/oauth/v1/applications"
}

func makeNewApplicationRequest() NewApplicationRequest {
	return NewApplicationRequest{
		UserAgent:  NewApplicationUserAgent,
		Culture:    NewApplicationCulture,
		EndpointId: "123",
	}
}

func makeNewApplicationResponse(meetingsUrl string) *NewApplicationResponse {
	return &NewApplicationResponse{
		Embedded: Embedded{
			OnlineMeetings: OnlineMeetings{
				OnlineMeetingsLinks: OnlineMeetingsLinks{
					MyOnlineMeetings: Href{Href: meetingsUrl},
				},
			},
		},
	}
}

func makeMeetingUrl(domain string, meettingsUrlWithoutHost string) string {
	return "https://" + domain + "/" + meettingsUrlWithoutHost
}

func makeNewMeetingRequest(mmUser model.User) NewMeetingRequest {
	return NewMeetingRequest{Subject: "Meeting created by " + mmUser.Username, AutomaticLeaderAssignment: "SameEnterprise"}
}

func makeNewMeetingResponse(meetingId string, domain string) NewMeetingResponse {
	return NewMeetingResponse{
		MeetingId: meetingId,
		JoinUrl:   domain + "/meetings/" + meetingId,
	}
}

func makePost(mmUser model.User, channelId string, createdMeeting NewMeetingResponse, pluginConfig configuration) *model.Post {
	return &model.Post{
		Id:        "",
		UserId:    mmUser.Id,
		ChannelId: channelId,
		Message:   "Meeting started at " + createdMeeting.JoinUrl + ".",
		Type:      "custom_s4b",
		Props: model.StringInterface{
			"from_webhook":      "true",
			"meeting_id":        createdMeeting.MeetingId,
			"meeting_link":      createdMeeting.JoinUrl,
			"meeting_personal":  true,
			"meeting_status":    "STARTED",
			"meeting_topic":     "Meeting created by " + mmUser.Username,
			"override_icon_url": pluginConfig.Domain + "/plugins/skype4business/api/v1/assets/profile.png",
			"override_username": "Skype for Business Plugin",
		},
	}
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

func (c *ClientMock) performRequestAndGetAuthHeader(url string) (*string, error) {
	ret := c.Called(url)

	if ret.Get(0) != nil && ret.Get(1) == nil {
		return ret.Get(0).(*string), nil
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
