// Copyright (c) 2017-present Mattermost, Inc. All Rights Reserved.
// See License for license information.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/mattermost/mattermost-server/model"
	"github.com/mattermost/mattermost-server/plugin"
)

const (
	POST_MEETING_KEY = "post_meeting_"
)

//todo tests
type Plugin struct {
	plugin.MattermostPlugin

	// configurationLock synchronizes access to the configuration.
	configurationLock sync.RWMutex

	// configuration is the active plugin configuration. Consult getConfiguration and
	// setConfiguration for usage.
	configuration *configuration
}

func (p *Plugin) OnActivate() error {
	if err := p.IsConfigurationValid(); err != nil {
		return err
	}

	return nil
}

func (p *Plugin) IsConfigurationValid() error {
	//todo
	return nil
}

func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	if err := p.IsConfigurationValid(); err != nil {
		http.Error(w, "This plugin is not configured.", http.StatusNotImplemented)
		return
	}

	path := r.URL.Path
	if strings.Contains(path, "/api/v1/popup/") {
		p.handlePopup(w, r)
	} else {
		switch path {
		case "/api/v1/client_id":
			p.handleClientId(w, r)
		case "/api/v1/meetings":
			p.handleStartMeeting(w, r)
		default:
			http.NotFound(w, r)
		}
	}
}

type StartMeetingRequest struct {
	ChannelId  string `json:"channel_id"`
	Personal   bool   `json:"personal"`
	Topic      string `json:"topic"`
	MeetingId  int    `json:"meeting_id"`
	MeetingURL string `json:"metting_url"`
}

type ClientIdResponse struct {
	ClientId string `json:"client_id"`
}

func (p *Plugin) handlePopup(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("<p>Creating the meeting...</p>"))
}

func (p *Plugin) handleClientId(w http.ResponseWriter, r *http.Request) {

	userId := r.Header.Get("Mattermost-User-Id")

	if userId == "" {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	config := p.getConfiguration()
	var response ClientIdResponse
	response.ClientId = config.ClientId

	if err := json.NewEncoder(w).Encode(&response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	return
}

func (p *Plugin) handleStartMeeting(w http.ResponseWriter, r *http.Request) {
	userId := r.Header.Get("Mattermost-User-Id")

	if userId == "" {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	var req StartMeetingRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	var user *model.User
	var err *model.AppError
	user, err = p.API.GetUser(userId)
	if err != nil {
		http.Error(w, err.Error(), err.StatusCode)
	}

	if _, err := p.API.GetChannelMember(req.ChannelId, user.Id); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	meetingId := req.MeetingId
	personal := req.Personal

	post := &model.Post{
		UserId:    user.Id,
		ChannelId: req.ChannelId,
		Message:   fmt.Sprintf("Meeting started at %s.", req.MeetingURL),
		Type:      "custom_s4b",
		Props: map[string]interface{}{
			"meeting_id":        meetingId,
			"meeting_link":      req.MeetingURL,
			"meeting_status":    "STARTED",
			"meeting_personal":  personal,
			"meeting_topic":     req.Topic,
			"from_webhook":      "true",
			"override_username": "Skype for Business",
			"override_icon_url": "", //todo
		},
	}

	if post, err := p.API.CreatePost(post); err != nil {
		http.Error(w, err.Error(), err.StatusCode)
		return
	} else {
		err = p.API.KVSet(fmt.Sprintf("%v%v", POST_MEETING_KEY, meetingId), []byte(post.Id))
		if err != nil {
			http.Error(w, err.Error(), err.StatusCode)
			return
		}
	}

	w.Write([]byte(fmt.Sprintf("%v", meetingId)))
}
