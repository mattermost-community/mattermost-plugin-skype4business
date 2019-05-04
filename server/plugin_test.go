package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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

	noAuthMeetingRequest := httptest.NewRequest("POST", "/api/v1/register_meeting_from_online_version", strings.NewReader("{\"channel_id\": \"thechannelid\"}"))

	personalMeetingRequest := httptest.NewRequest("POST", "/api/v1/register_meeting_from_online_version", strings.NewReader("{\"channel_id\": \"thechannelid\", \"meeting_id\": \"L30IC51J\", \"personal\": true}"))
	personalMeetingRequest.Header.Add("Mattermost-User-Id", "theuserid")

	for name, tc := range map[string]struct {
		Request            *http.Request
		CreatePostError    *model.AppError
		ExpectedStatusCode int
	}{
		"UnauthorizedMeetingRequest": {
			Request:            noAuthMeetingRequest,
			ExpectedStatusCode: http.StatusUnauthorized,
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
			api.On("UpdatePost", mock.AnythingOfType("*model.Post")).Return(&model.Post{}, (*model.AppError)(nil))
			api.On("KVSet", fmt.Sprintf("%v%v", POST_MEETING_KEY, "L30IC51J"), mock.AnythingOfType("[]uint8")).Return((*model.AppError)(nil))

			p := Plugin{}
			p.setConfiguration(&configuration{
				ClientId: "123123123",
			})
			p.SetAPI(api)
			err := p.OnActivate()
			assert.Nil(t, err)

			w := httptest.NewRecorder()
			p.ServeHTTP(&plugin.Context{}, w, tc.Request)
			assert.Equal(t, tc.ExpectedStatusCode, w.Result().StatusCode)
		})
	}
}
