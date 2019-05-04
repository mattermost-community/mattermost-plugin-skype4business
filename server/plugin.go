// Copyright (c) 2017-present Mattermost, Inc. All Rights Reserved.
// See License for license information.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/mattermost/mattermost-server/model"
	"github.com/mattermost/mattermost-server/plugin"
)

const (
	POST_MEETING_KEY               = "post_meeting_"
	POST_MEETING_TYPE              = "custom_s4b"
	POST_MEETING_OVERRIDE_USERNAME = "Skype for Business"
	NEW_APPLICATION_USER_AGENT     = "mm_skype4b_plugin"
	NEW_APPLICATION_CULTURE        = "en-US"
	WS_EVENT_AUTHENTICATED         = "authenticated"
)

type Plugin struct {
	plugin.MattermostPlugin

	// configurationLock synchronizes access to the configuration.
	configurationLock sync.RWMutex

	// configuration is the active plugin configuration. Consult getConfiguration and
	// setConfiguration for usage.
	configuration *configuration
}

func (p *Plugin) OnActivate() error {
	config := p.getConfiguration()
	if err := config.IsValid(); err != nil {
		return err
	}

	return nil
}

func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	config := p.getConfiguration()
	if err := config.IsValid(); err != nil {
		http.Error(w, "This plugin is not configured.", http.StatusNotImplemented)
		return
	}

	path := r.URL.Path
	switch path {
	case "/api/v1/is_server_version":
		p.handleIsServerVersion(w, r)
	case "/api/v1/create_meeting_in_server_version":
		p.handleCreateMeetingInServerVersion(w, r)
	case "/api/v1/client_id":
		p.handleClientId(w, r)
	case "/api/v1/auth":
		p.handleAuthorizeInADD(w, r)
	case "/api/v1/auth_redirect":
		p.completeAuthorizeInADD(w, r)
	case "/api/v1/register_meeting_from_online_version":
		p.handleRegisterMeetingFromOnlineVersion(w, r)
	default:
		http.NotFound(w, r)
	}
}

type StartMeetingRequest struct {
	ChannelId  string `json:"channel_id"`
	Personal   bool   `json:"personal"`
	Topic      string `json:"topic"`
	MeetingId  string `json:"meeting_id"`
	MeetingURL string `json:"metting_url"`
}

type StartServerMeetingRequest struct {
	ChannelId string `json:"channel_id"`
	Personal  bool   `json:"personal"`
}

type ClientIdResponse struct {
	ClientId string `json:"client_id"`
}

type IsServerVersionResponse struct {
	IsServerVersion string `json:"is_server_version"`
}

type State struct {
	userId string
	State  string
}

type NewMeetingRequest struct {
	Subject string `json:"subject"`
}

type NewMeetingResponse struct {
	JoinUrl   string `json:"joinUrl"`
	MeetingId string `json:"onlineMeetingId"`
}

type DiscoveryResponse struct {
	Links struct {
		User struct {
			Href string `json:"href"`
		} `json:"user"`
		Applications struct {
			Href string `json:"href"`
		} `json:"applications"`
		Redirect struct {
			Href string `json:"href"`
		} `json:"redirect"`
	} `json:"_links"`
}

type NewApplicationRequest struct {
	UserAgent  string `json:"UserAgent"`
	EndpointId string `json:"EndpointId"`
	Culture    string `json:"Culture"`
}

type NewApplicationResponse struct {
	Embedded struct {
		OnlineMeetings struct {
			OnlineMeetingsLinks struct {
				MyOnlineMeetings struct {
					Href string `json:"href"`
				} `json:"myOnlineMeetings"`
			} `json:"_links"`
		} `json:"onlineMeetings"`
	} `json:"_embedded"`
}

type AuthResponse struct {
	Access_token string
}

type UserResourceResponse struct {
	Links struct {
		Applications struct {
			Href string `json:"href"`
		} `json:"applications"`
		Redirect struct {
			Href string `json:"href"`
		} `json:"redirect"`
	} `json:"_links"`
}

type APIError struct {
	Message string
}

type ApplicationState struct {
	OnlineMeetingsUrl string
	ApplicationsUrl   string
	Resource          string
	Token             string
}

func (p *Plugin) handleAuthorizeInADD(w http.ResponseWriter, r *http.Request) {

	userId := r.URL.Query().Get("mattermost_user_id")

	if userId == "" {
		fmt.Println("Not authorized")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	encodedAuthUrl := r.URL.Query().Get("navigateTo")
	if encodedAuthUrl == "" {
		fmt.Println("Url Param 'navigateTo' is missing")
		http.Error(w, "Url Param 'navigateTo' is missing", http.StatusBadRequest)
		return
	}

	authUrl, err := url.QueryUnescape(encodedAuthUrl)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, "cannot decode url", http.StatusBadRequest)
		return
	}

	authUrlValues, err := url.ParseQuery(authUrl)
	if err != nil {
		fmt.Println("cannot parse url")
		http.Error(w, "cannot parse url", http.StatusBadRequest)
		return
	}

	state := authUrlValues.Get("state")
	if state == "" {
		fmt.Println("Url Param 'state' is missing")
		http.Error(w, "Url Param 'state' is missing", http.StatusBadRequest)
		return
	}

	p.API.KVSet(state, []byte(strings.TrimSpace(userId)))

	http.Redirect(w, r, authUrl, http.StatusFound)
}

func (p *Plugin) completeAuthorizeInADD(w http.ResponseWriter, r *http.Request) {

	idToken := r.FormValue("id_token")

	if idToken == "" {
		http.Error(w, "missing id_token", http.StatusBadRequest)
		return
	}

	state := r.FormValue("state")

	if state == "" {
		http.Error(w, "missing state", http.StatusBadRequest)
		return
	}

	userId, err := p.API.KVGet(state)

	if err != nil {
		fmt.Println(err.Message)
		http.Error(w, "cannot get stored state", http.StatusBadRequest)
		return
	} else if userId == nil {
		http.Error(w, "missing stored state", http.StatusBadRequest)
		return
	}

	err = p.API.KVDelete(state)
	if err != nil {
		fmt.Println("cannot delete stored state", err)
	}

	p.API.PublishWebSocketEvent(WS_EVENT_AUTHENTICATED, map[string]interface{}{
		"token": idToken,
		"state": state,
	}, &model.WebsocketBroadcast{
		UserId: strings.TrimSpace(string(userId)),
	})

	html := `
		<!DOCTYPE html>
		<html>
			<head>
				<script>
					setTimeout(function() {
						window.close()
					}, 1000)
				</script>
			</head>
			<body>
				<p>Creating the meeting...</p>
				<p>You can close this window.</p>
			</body>
		</html>
		`

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
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

func (p *Plugin) handleIsServerVersion(w http.ResponseWriter, r *http.Request) {

	userId := r.Header.Get("Mattermost-User-Id")
	if userId == "" {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	config := p.getConfiguration()
	if config == nil {
		http.Error(w, "Cannot fetch configuration", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var response IsServerVersionResponse
	if p.getConfiguration().IsServerVersion {
		response.IsServerVersion = "Y"
	} else {
		response.IsServerVersion = "N"
	}

	if err := json.NewEncoder(w).Encode(&response); err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	return
}

func (p *Plugin) handleRegisterMeetingFromOnlineVersion(w http.ResponseWriter, r *http.Request) {

	userId := r.Header.Get("Mattermost-User-Id")
	if userId == "" {
		fmt.Println("Request doesn't have Mattermost-User-Id header")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	user, err := p.API.GetUser(userId)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), err.StatusCode)
		return
	} else if user == nil {
		fmt.Println("User is nil")
		http.Error(w, "User is nil", http.StatusUnauthorized)
		return
	}

	config := p.getConfiguration()
	if config == nil {
		fmt.Println("Cannot fetch configuration")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	} else if config.IsServerVersion {
		fmt.Println("Server version is set")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req StartMeetingRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := p.API.GetChannelMember(req.ChannelId, user.Id); err != nil {
		fmt.Println(err.Error())
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	post := &model.Post{
		UserId:    user.Id,
		ChannelId: req.ChannelId,
		Message:   fmt.Sprintf("Meeting started at %s.", req.MeetingURL),
		Type:      POST_MEETING_TYPE,
		Props: map[string]interface{}{
			"meeting_id":        req.MeetingId,
			"meeting_link":      req.MeetingURL,
			"meeting_personal":  req.Personal,
			"meeting_topic":     req.Topic,
			"override_username": POST_MEETING_OVERRIDE_USERNAME,
			"meeting_status":    "STARTED",
			"from_webhook":      "true",
			"override_icon_url": "", //todo
		},
	}

	if post, err := p.API.CreatePost(post); err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), err.StatusCode)
		return
	} else {
		err = p.API.KVSet(fmt.Sprintf("%v%v", POST_MEETING_KEY, req.MeetingId), []byte(post.Id))
		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, err.Error(), err.StatusCode)
			return
		}
	}

	w.Write([]byte(fmt.Sprintf("%v", req.MeetingId)))
}

func (p *Plugin) handleCreateMeetingInServerVersion(w http.ResponseWriter, r *http.Request) {

	config := p.getConfiguration()
	if !config.IsServerVersion {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	userId := r.Header.Get("Mattermost-User-Id")
	if userId == "" {
		fmt.Println("Request doesn't have Mattermost-User-Id header")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	var user *model.User
	var appError *model.AppError
	user, appError = p.API.GetUser(userId)
	if appError != nil {
		fmt.Println(appError.Error())
		http.Error(w, appError.Error(), appError.StatusCode)
		return
	} else if user == nil {
		fmt.Println("User is nil")
		http.Error(w, "User is nil", http.StatusUnauthorized)
		return
	}

	var req StartServerMeetingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if _, err := p.API.GetChannelMember(req.ChannelId, user.Id); err != nil {
		fmt.Println(err.Error())
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	applicationState, apiErr := p.fetchOnlineMeetingsUrl()
	if apiErr != nil {
		fmt.Println(apiErr.Message)
		http.Error(w, apiErr.Message, http.StatusInternalServerError)
		return
	}

	newMeetingRequestBytes, err := json.Marshal(NewMeetingRequest{
		Subject: "Meeting created by " + user.Username,
	})
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("222")

	newMeetingRequest, err := http.NewRequest("POST", applicationState.OnlineMeetingsUrl, bytes.NewBuffer(newMeetingRequestBytes))
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newMeetingRequest.Header.Set("Authorization", "Bearer "+applicationState.Token)
	newMeetingRequest.Header.Set("Accept", "application/json")
	newMeetingRequest.Header.Set("Content-Type", "application/json")

	newMeetingResponse, err := p.getClient().Do(newMeetingRequest)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newMeetingResponseBytes, err := ioutil.ReadAll(newMeetingResponse.Body)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newMeetingResponseBody := &NewMeetingResponse{}
	err = json.Unmarshal(newMeetingResponseBytes, newMeetingResponseBody)
	if err != nil {
		fmt.Println("respo", string(newMeetingResponseBytes))
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("66")

	post := &model.Post{
		UserId:    user.Id,
		ChannelId: req.ChannelId,
		Message:   fmt.Sprintf("Meeting started at %s.", newMeetingResponseBody.JoinUrl),
		Type:      POST_MEETING_TYPE,
		Props: map[string]interface{}{
			"meeting_id":        newMeetingResponseBody.MeetingId,
			"meeting_link":      newMeetingResponseBody.JoinUrl,
			"meeting_personal":  req.Personal,
			"override_username": POST_MEETING_OVERRIDE_USERNAME,
			"meeting_topic":     "Meeting created by " + user.Username,
			"meeting_status":    "STARTED",
			"from_webhook":      "true",
			"override_icon_url": "", //todo
		},
	}

	if post, err := p.API.CreatePost(post); err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else {
		err = p.API.KVSet(fmt.Sprintf("%v%v", POST_MEETING_KEY, newMeetingResponseBody.MeetingId), []byte(post.Id))
		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if err := json.NewEncoder(w).Encode(&newMeetingResponseBody); err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	return
}

func (p *Plugin) fetchOnlineMeetingsUrl() (*ApplicationState, *APIError) {

	config := p.getConfiguration()
	discoveryUrl := "https://lyncdiscover." + config.Domain
	discoveryRequest, err := http.NewRequest("GET", discoveryUrl, nil)
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}

	discoveryResponse, err := p.getClient().Do(discoveryRequest)
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}

	discoveryResponseBytes, err := ioutil.ReadAll(discoveryResponse.Body)
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}
	discoveryResponseBody := &DiscoveryResponse{}
	err = json.Unmarshal(discoveryResponseBytes, discoveryResponseBody)
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}

	applicationState, apiError := p.getApplicationState(discoveryResponseBody.Links.User.Href)
	if apiError != nil {
		return nil, apiError
	}

	applicationsResourceRequestBody, _ := json.Marshal(NewApplicationRequest{
		UserAgent:  NEW_APPLICATION_USER_AGENT,
		Culture:    NEW_APPLICATION_CULTURE,
		EndpointId: "123",
	})

	applicationsResourceRequest, err := http.NewRequest("POST", applicationState.ApplicationsUrl, bytes.NewBuffer([]byte(applicationsResourceRequestBody)))
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}

	applicationsResourceRequest.Header.Set("Authorization", "Bearer "+applicationState.Token)
	applicationsResourceRequest.Header.Set("Accept", "application/json")
	applicationsResourceRequest.Header.Set("Content-Type", "application/json")

	applicationsResourceResponse, err := p.getClient().Do(applicationsResourceRequest)
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}

	applicationsResourceResponseBody := &NewApplicationResponse{}
	applicationsResourceResponseBytes, err := ioutil.ReadAll(applicationsResourceResponse.Body)
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}

	err = json.Unmarshal(applicationsResourceResponseBytes, applicationsResourceResponseBody)
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}

	applicationState.OnlineMeetingsUrl = "https://" + applicationState.Resource + "/" + applicationsResourceResponseBody.Embedded.OnlineMeetings.OnlineMeetingsLinks.MyOnlineMeetings.Href

	return applicationState, nil
}

func (p *Plugin) getApplicationState(userResourceUrl string) (*ApplicationState, *APIError) {
	config := p.getConfiguration()

	resourceRegex := regexp.MustCompile(`https:\/\/(.*)\/Autodiscover\/`)
	resourceRegexMatch := resourceRegex.FindStringSubmatch(userResourceUrl)
	resourceName := resourceRegexMatch[1]

	tokenUrl := "https://lyncweb." + config.Domain + "/webticket/oauthtoken"
	authResponse, err := p.getClient().PostForm(tokenUrl,
		url.Values{
			"grant_type": {"password"},
			"username":   {config.Username},
			"password":   {config.Password},
			"resource":   {resourceName},
		})
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}

	authResponseBytes, err := ioutil.ReadAll(authResponse.Body)
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}

	authResponseBody := &AuthResponse{}
	err = json.Unmarshal(authResponseBytes, authResponseBody)
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}

	Token := authResponseBody.Access_token

	userResourceRequest, err := http.NewRequest("GET", userResourceUrl, nil)
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}

	userResourceRequest.Header.Set("Authorization", "Bearer "+Token)
	userResourceRequest.Header.Set("Accept", "application/json")
	userResourceRequest.Header.Set("Content-Type", "application/json")

	userResourceResponse, err := p.getClient().Do(userResourceRequest)
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}

	userResourceResponseBytes, err := ioutil.ReadAll(userResourceResponse.Body)
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}

	userResourceResponseBody := &UserResourceResponse{}
	err = json.Unmarshal(userResourceResponseBytes, userResourceResponseBody)
	if err != nil {
		return nil, &APIError{
			Message: err.Error(),
		}
	}

	if userResourceResponseBody.Links.Applications.Href != "" {
		return &ApplicationState{
			ApplicationsUrl: userResourceResponseBody.Links.Applications.Href,
			Resource:        resourceName,
			Token:           Token,
		}, nil
	} else if userResourceResponseBody.Links.Redirect.Href != "" {
		return p.getApplicationState(userResourceResponseBody.Links.Redirect.Href)
	} else {
		return nil, &APIError{
			Message: "Unexpected error during creating an application",
		}
	}
}

func (p *Plugin) getClient() *http.Client {
	var transCfg = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: transCfg}
}
