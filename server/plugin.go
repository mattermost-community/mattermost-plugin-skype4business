// Copyright (c) 2017-present Mattermost, Inc. All Rights Reserved.
// See License for license information.

package main

import (
	"encoding/json"
	"fmt"
	"github.com/mattermost/mattermost-server/mlog"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/mattermost/mattermost-server/model"
	"github.com/mattermost/mattermost-server/plugin"
)

const (
	POST_MEETING_KEY               = "post_meeting_"
	POST_MEETING_TYPE              = "custom_s4b"
	POST_MEETING_OVERRIDE_USERNAME = "Skype for Business Plugin"
	NEW_APPLICATION_USER_AGENT     = "mm_skype4b_plugin"
	NEW_APPLICATION_CULTURE        = "en-US"
	WS_EVENT_AUTHENTICATED         = "authenticated"
	ROOT_URL_KEY                   = "root_url"
)

type IClient interface {
	authenticate(url string, body url.Values) (*AuthResponse, error)
	createNewApplication(url string, body interface{}, token string) (*NewApplicationResponse, error)
	createNewMeeting(url string, body interface{}, token string) (*NewMeetingResponse, error)
	performDiscovery(url string) (*DiscoveryResponse, error)
	performRequestAndGetAuthHeader(url string) (*string, error)
	readUserResource(url string, token string) (*UserResourceResponse, error)
}

type Plugin struct {
	plugin.MattermostPlugin

	// configurationLock synchronizes access to the configuration.
	configurationLock sync.RWMutex

	// configuration is the active plugin configuration. Consult getConfiguration and
	// setConfiguration for usage.
	configuration *configuration

	client IClient
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
	case "/api/v1/product_type":
		p.handleProductType(w, r)
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
	case "/api/v1/assets/profile.png":
		p.handleProfileImage(w, r)
	default:
		http.NotFound(w, r)
	}
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

func (p *Plugin) handleProductType(w http.ResponseWriter, r *http.Request) {

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

	if err := json.NewEncoder(w).Encode(ProductTypeResponse{
		ProductType: p.getConfiguration().ProductType,
	}); err != nil {
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
	} else if config.ProductType == PRODUCT_TYPE_SERVER {
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

	serverConfiguration := p.API.GetConfig()

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
			"override_icon_url": path.Join(*serverConfiguration.ServiceSettings.SiteURL, "plugins", manifest.Id, "api", "v1", "assets", "profile.png"),
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
	if config.ProductType == PRODUCT_TYPE_ONLINE {
		mlog.Error("Cannot create meeting in the server version when the online is set")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	userId := r.Header.Get("Mattermost-User-Id")
	if userId == "" {
		mlog.Error("Request doesn't have Mattermost-User-Id header")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	var user *model.User
	var appError *model.AppError
	user, appError = p.API.GetUser(userId)
	if appError != nil {
		mlog.Error("Error getting user: " + appError.Error())
		http.Error(w, appError.Error(), appError.StatusCode)
		return
	} else if user == nil {
		mlog.Error("User with that id doesn't exist: " + userId)
		http.Error(w, "User is nil", http.StatusUnauthorized)
		return
	}

	var req StartServerMeetingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mlog.Error("Error decoding JSON body: " + err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if _, err := p.API.GetChannelMember(req.ChannelId, user.Id); err != nil {
		mlog.Error("Error getting channel member: " + err.Error())
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	applicationState, apiErr := p.fetchOnlineMeetingsUrl()
	if apiErr != nil {
		mlog.Error("Error fetching meetings resource url: " + apiErr.Message)
		http.Error(w, apiErr.Message, http.StatusInternalServerError)
		return
	}

	newMeetingResponse, err := p.client.createNewMeeting(
		applicationState.OnlineMeetingsUrl,
		NewMeetingRequest{
			Subject:                   "Meeting created by " + user.Username,
			AutomaticLeaderAssignment: "SameEnterprise",
		},
		applicationState.Token,
	)
	if err != nil {
		mlog.Error("Error creating a new meeting: " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	serverConfiguration := p.API.GetConfig()

	post := &model.Post{
		UserId:    user.Id,
		ChannelId: req.ChannelId,
		Message:   fmt.Sprintf("Meeting started at %s.", newMeetingResponse.JoinUrl),
		Type:      POST_MEETING_TYPE,
		Props: map[string]interface{}{
			"meeting_id":        newMeetingResponse.MeetingId,
			"meeting_link":      newMeetingResponse.JoinUrl,
			"meeting_personal":  req.Personal,
			"override_username": POST_MEETING_OVERRIDE_USERNAME,
			"meeting_topic":     "Meeting created by " + user.Username,
			"meeting_status":    "STARTED",
			"from_webhook":      "true",
			"override_icon_url": path.Join(*serverConfiguration.ServiceSettings.SiteURL, "plugins", manifest.Id, "api", "v1", "assets", "profile.png"),
		},
	}

	if post, err := p.API.CreatePost(post); err != nil {
		mlog.Error("Error creating a new post with the new meeting: " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else {
		err = p.API.KVSet(fmt.Sprintf("%v%v", POST_MEETING_KEY, newMeetingResponse.MeetingId), []byte(post.Id))
		if err != nil {
			mlog.Error("Error writing meeting id to the database: " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if err := json.NewEncoder(w).Encode(&newMeetingResponse); err != nil {
		mlog.Error("Error encoding the new meeting response: " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	return
}

func (p *Plugin) handleProfileImage(w http.ResponseWriter, r *http.Request) {
	bundlePath, err := p.API.GetBundlePath()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	img, err := os.Open(filepath.Join(bundlePath, "assets", "profile.png"))
	if err != nil {
		http.NotFound(w, r)
		mlog.Error("Unable to read Skype 4 Business plugin profile image, err=" + err.Error())
		return
	}
	defer img.Close()

	w.Header().Set("Content-Type", "image/png")
	io.Copy(w, img)
}

func (p *Plugin) fetchOnlineMeetingsUrl() (*ApplicationState, *APIError) {
	rootUrl, apiErr := p.getRootUrl()
	if apiErr != nil {
		return nil, apiErr
	}

	applicationState, apiError := p.getApplicationState(*rootUrl)
	if apiError != nil {
		return nil, apiError
	}

	newApplicationResponse, err := p.client.createNewApplication(
		applicationState.ApplicationsUrl,
		NewApplicationRequest{
			UserAgent:  NEW_APPLICATION_USER_AGENT,
			Culture:    NEW_APPLICATION_CULTURE,
			EndpointId: "123",
		},
		applicationState.Token,
	)
	if err != nil {
		return nil, &APIError{Message: "Error creating a new application: " + err.Error()}
	}

	applicationState.OnlineMeetingsUrl = "https://" + applicationState.Resource + "/" + newApplicationResponse.Embedded.OnlineMeetings.OnlineMeetingsLinks.MyOnlineMeetings.Href

	return applicationState, nil
}

func (p *Plugin) getApplicationState(discoveryUrl string) (*ApplicationState, *APIError) {
	config := p.getConfiguration()

	DiscoveryResponse, err := p.client.performDiscovery(discoveryUrl)
	if err != nil {
		return nil, &APIError{Message: "Error performing autodiscovery: " + err.Error()}
	}

	authHeader, err := p.client.performRequestAndGetAuthHeader(DiscoveryResponse.Links.User.Href)
	if err != nil {
		return nil, &APIError{Message: "Error performing request to get authentication header: " + err.Error()}
	}

	tokenUrl, apiErr := p.extractTokenUrl(*authHeader)
	if apiErr != nil {
		return nil, apiErr
	}

	userResourceUrl := DiscoveryResponse.Links.User.Href
	resourceName := p.extractResourceNameFromUserUrl(userResourceUrl)
	authResponse, err := p.authenticate(*tokenUrl, resourceName, *config)
	if err != nil {
		return nil, &APIError{Message: "Error during authentication: " + err.Error()}
	}

	userResourceResponse, err := p.client.readUserResource(userResourceUrl, authResponse.Access_token)
	if err != nil {
		return nil, &APIError{Message: "Error reading user resource: " + err.Error()}
	}

	applicationsUrl := userResourceResponse.Links.Applications.Href
	if applicationsUrl != "" {

		applicationsResourceName := p.extractResourceNameFromApplicationsUrl(applicationsUrl)
		if applicationsResourceName != resourceName {
			mlog.Warn("Resource from applications url is not the same as resource name from user url")

			authHeader, err := p.client.performRequestAndGetAuthHeader(applicationsUrl)
			if err != nil {
				return nil, &APIError{
					Message: "Error performing request to get authentication header from new resource: " + err.Error(),
				}
			}

			tokenUrl, apiErr := p.extractTokenUrl(*authHeader)
			if apiErr != nil {
				return nil, apiErr
			}

			authResponse, err = p.authenticate(*tokenUrl, applicationsResourceName, *config)
			if err != nil {
				return nil, &APIError{Message: "Error during authentication in new resource: " + err.Error()}
			}
		}

		return &ApplicationState{
			ApplicationsUrl: applicationsUrl,
			Resource:        applicationsResourceName,
			Token:           authResponse.Access_token,
		}, nil
	} else if userResourceResponse.Links.Redirect.Href != "" {
		return p.getApplicationState(userResourceResponse.Links.Redirect.Href)
	} else {
		return nil, &APIError{
			Message: "Neither applications resource or redirect resource fetched from user resource",
		}
	}
}

func (p *Plugin) getRootUrl() (*string, *APIError) {
	rootUrlBytes, appErr := p.API.KVGet(ROOT_URL_KEY)
	if appErr != nil {
		return nil, &APIError{Message: "Cannot fetch the root url from the database: " + appErr.Error()}
	}

	if rootUrlBytes != nil {
		rootUrl := string(rootUrlBytes)
		return &rootUrl, nil
	}

	rootUrl, err := p.determineRootUrl(p.getConfiguration().Domain)
	if err != nil {
		return nil, err
	}

	_ = p.API.KVSet(ROOT_URL_KEY, []byte(*rootUrl))

	return rootUrl, nil
}

func (p *Plugin) determineRootUrl(domain string) (*string, *APIError) {
	for _, o := range []struct {
		url  string
		name string
	}{
		{
			url:  "https://lyncdiscoverinternal." + domain,
			name: "internal https",
		},
		{
			url:  "https://lyncdiscover." + domain,
			name: "external https",
		},
		{
			url:  "http://lyncdiscoverinternal." + domain,
			name: "internal http",
		},
		{
			url:  "http://lyncdiscover." + domain,
			name: "external http",
		},
	} {
		_, err := p.client.performDiscovery(o.url)
		if err == nil {
			return &o.url, nil
		} else {
			mlog.Warn("Error performing autodiscovery with " + o.name + " root URL: " + err.Error())
		}
	}

	return nil, &APIError{
		Message: "Cannot determine root URL. Check if your DNS server has a lyncdiscover or lyncdiscoverinternal record.",
	}
}

func (p *Plugin) extractTokenUrl(authHeader string) (*string, *APIError) {
	webTicketUrlRegexMatch := regexp.MustCompile(`href=(.*?),`).FindStringSubmatch(authHeader)
	if len(webTicketUrlRegexMatch) < 1 {
		return nil, &APIError{
			Message: "Cannot extract webTicket URL from WWW-AUTHENTICATE header! Full header value: " + authHeader,
		}
	}
	webTicketUrl := strings.ReplaceAll(webTicketUrlRegexMatch[1], "\"", "")

	grantTypeRegexMatch := regexp.MustCompile(`grant_type="(.*?)"`).FindStringSubmatch(authHeader)
	if len(grantTypeRegexMatch) < 1 {
		return nil, &APIError{
			Message: "Cannot extract grant types from WWW-AUTHENTICATE header! Full header value: " + authHeader,
		}
	}
	grantTypes := grantTypeRegexMatch[1]

	if !regexp.MustCompile("password").MatchString(grantTypes) {
		return nil, &APIError{
			Message: "WWW-AUTHENTICATE header doesn't have the password grant type! Full header value: " + authHeader,
		}
	}

	return &webTicketUrl, nil
}

func (p *Plugin) authenticate(tokenUrl string, resourceName string, config configuration) (*AuthResponse, error) {
	return p.client.authenticate(tokenUrl, url.Values{
		"grant_type": {"password"},
		"username":   {config.Username},
		"password":   {config.Password},
		"resource":   {resourceName},
	})
}

func (p *Plugin) extractResourceNameFromUserUrl(userUrl string) string {
	resourceRegex := regexp.MustCompile(`https:\/\/(.*)\/Autodiscover\/`)
	resourceRegexMatch := resourceRegex.FindStringSubmatch(userUrl)
	return resourceRegexMatch[1]
}

func (p *Plugin) extractResourceNameFromApplicationsUrl(applicationsUrl string) string {
	resourceRegex := regexp.MustCompile(`https:\/\/(.*)\/ucwa\/`)
	resourceRegexMatch := resourceRegex.FindStringSubmatch(applicationsUrl)
	return resourceRegexMatch[1]
}
