// Copyright (c) 2017-present Mattermost, Inc. All Rights Reserved.
// See License for license information.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/mattermost/mattermost-server/v5/mlog"

	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/mattermost/mattermost-server/v5/plugin"
)

const (
	// PostMeetingKey is a prefix added to each post's ID created by the plugin.
	PostMeetingKey = "post_meeting_"
	// PostMeetingType represents a type of posts created by the plugin.
	PostMeetingType = "custom_s4b"
	// PostMeetingOverrideUsername overrides the name displayed as the sender of a post with a meeting created by the plugin.
	PostMeetingOverrideUsername = "Skype for Business Plugin"
	// NewApplicationUserAgent is used by UCWA for identifying messages sent on behalf of the plugin.
	NewApplicationUserAgent = "mm_skype4b_plugin"
	// NewApplicationCulture represents the culture used by the plugin.
	// Used only by S4B Server.
	NewApplicationCulture = "en-US"
	// WsEventAuthenticated represents type of PublishWebSocketEvent broadcasted after authentication in Azure AD.
	// Used only by S4B Online.
	WsEventAuthenticated = "authenticated"
	// RootURLKey represents a key in KV Store where is saved a full URL used to perform autodiscovery is saved.
	// Used only by S4B Server.
	RootURLKey = "root_url"
)

// IClient is an interface of a struct that performs requests to UCWA.
type IClient interface {
	authenticate(url string, body url.Values) (*AuthResponse, error)
	createNewApplication(url string, body interface{}, token string) (*NewApplicationResponse, error)
	createNewMeeting(url string, body interface{}, token string) (*NewMeetingResponse, error)
	performDiscovery(url string) (*DiscoveryResponse, error)
	performRequestAndGetAuthHeader(url string) (*string, error)
	readUserResource(url string, token string) (*UserResourceResponse, error)
}

// Plugin represents the plugin api.
type Plugin struct {
	plugin.MattermostPlugin

	// configurationLock synchronizes access to the configuration.
	configurationLock sync.RWMutex

	// configuration is the active plugin configuration. Consult getConfiguration and
	// setConfiguration for usage.
	configuration *configuration

	client IClient
}

// OnActivate is a method that is called once the plugin is activated.
// It checks if a provided configuration of the plugin is valid.
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
		p.handleClientID(w, r)
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

	userID := r.URL.Query().Get("mattermost_user_id")

	if userID == "" {
		fmt.Println("Not authorized")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	encodedAuthURL := r.URL.Query().Get("navigateTo")
	if encodedAuthURL == "" {
		fmt.Println("Url Param 'navigateTo' is missing")
		http.Error(w, "Url Param 'navigateTo' is missing", http.StatusBadRequest)
		return
	}

	authURL, err := url.QueryUnescape(encodedAuthURL)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, "cannot decode url", http.StatusBadRequest)
		return
	}

	authURLValues, err := url.ParseQuery(authURL)
	if err != nil {
		fmt.Println("cannot parse url")
		http.Error(w, "cannot parse url", http.StatusBadRequest)
		return
	}

	state := authURLValues.Get("state")
	if state == "" {
		fmt.Println("Url Param 'state' is missing")
		http.Error(w, "Url Param 'state' is missing", http.StatusBadRequest)
		return
	}

	p.API.KVSet(state, []byte(strings.TrimSpace(userID)))

	http.Redirect(w, r, authURL, http.StatusFound)
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

	userID, err := p.API.KVGet(state)

	if err != nil {
		fmt.Println(err.Message)
		http.Error(w, "cannot get stored state", http.StatusBadRequest)
		return
	}

	if userID == nil {
		http.Error(w, "missing stored state", http.StatusBadRequest)
		return
	}

	err = p.API.KVDelete(state)
	if err != nil {
		fmt.Println("cannot delete stored state", err)
	}

	p.API.PublishWebSocketEvent(WsEventAuthenticated, map[string]interface{}{
		"token": idToken,
		"state": state,
	}, &model.WebsocketBroadcast{
		UserId: strings.TrimSpace(string(userID)),
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

func (p *Plugin) handleClientID(w http.ResponseWriter, r *http.Request) {

	userID := r.Header.Get("Mattermost-User-Id")

	if userID == "" {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	config := p.getConfiguration()
	var response ClientIDResponse
	response.ClientID = config.ClientID

	if err := json.NewEncoder(w).Encode(&response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	return
}

func (p *Plugin) handleProductType(w http.ResponseWriter, r *http.Request) {

	userID := r.Header.Get("Mattermost-User-Id")
	if userID == "" {
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

	userID := r.Header.Get("Mattermost-User-Id")
	if userID == "" {
		fmt.Println("Request doesn't have Mattermost-User-Id header")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	user, appErr := p.API.GetUser(userID)
	if appErr != nil {
		fmt.Println(appErr.Error())
		http.Error(w, appErr.Error(), appErr.StatusCode)
		return
	}

	if user == nil {
		fmt.Println("User is nil")
		http.Error(w, "User is nil", http.StatusUnauthorized)
		return
	}

	config := p.getConfiguration()
	if config == nil {
		fmt.Println("Cannot fetch configuration")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if config.ProductType == productTypeServer {
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

	if _, appErr = p.API.GetChannelMember(req.ChannelID, user.Id); appErr != nil {
		fmt.Println(appErr.Error())
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	serverConfiguration := p.API.GetConfig()

	post := &model.Post{
		UserId:    user.Id,
		ChannelId: req.ChannelID,
		Message:   fmt.Sprintf("Meeting started at %s.", req.MeetingURL),
		Type:      PostMeetingType,
		Props: map[string]interface{}{
			"meeting_id":        req.MeetingID,
			"meeting_link":      req.MeetingURL,
			"meeting_personal":  req.Personal,
			"meeting_topic":     req.Topic,
			"override_username": PostMeetingOverrideUsername,
			"meeting_status":    "STARTED",
			"from_webhook":      "true",
			"override_icon_url": path.Join(*serverConfiguration.ServiceSettings.SiteURL, "plugins", manifest.ID, "api", "v1", "assets", "profile.png"),
		},
	}

	post, appErr = p.API.CreatePost(post)
	if appErr != nil {
		fmt.Println(appErr.Error())
		http.Error(w, appErr.Error(), appErr.StatusCode)
		return
	}

	if appErr = p.API.KVSet(fmt.Sprintf("%v%v", PostMeetingKey, req.MeetingID), []byte(post.Id)); appErr != nil {
		fmt.Println(appErr.Error())
		http.Error(w, appErr.Error(), appErr.StatusCode)
		return
	}

	w.Write([]byte(fmt.Sprintf("%v", req.MeetingID)))
}

func (p *Plugin) handleCreateMeetingInServerVersion(w http.ResponseWriter, r *http.Request) {
	config := p.getConfiguration()
	if config.ProductType == productTypeOnline {
		mlog.Error("Cannot create meeting in the server version when the online is set")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	userID := r.Header.Get("Mattermost-User-Id")
	if userID == "" {
		mlog.Error("Request doesn't have Mattermost-User-Id header")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	var user *model.User
	var appError *model.AppError
	user, appError = p.API.GetUser(userID)
	if appError != nil {
		mlog.Error("Error getting user: " + appError.Error())
		http.Error(w, appError.Error(), appError.StatusCode)
		return
	}

	if user == nil {
		mlog.Error("User with that id doesn't exist: " + userID)
		http.Error(w, "User is nil", http.StatusUnauthorized)
		return
	}

	var req StartServerMeetingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mlog.Error("Error decoding JSON body: " + err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := p.API.GetChannelMember(req.ChannelID, user.Id); err != nil {
		mlog.Error("Error getting channel member: " + err.Error())
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	applicationState, apiErr := p.fetchOnlineMeetingsURL()
	if apiErr != nil {
		mlog.Error("Error fetching meetings resource url: " + apiErr.Message)
		http.Error(w, apiErr.Message, http.StatusInternalServerError)
		return
	}

	newMeetingResponse, err := p.client.createNewMeeting(
		applicationState.OnlineMeetingsURL,
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
		ChannelId: req.ChannelID,
		Message:   fmt.Sprintf("Meeting started at %s.", newMeetingResponse.JoinURL),
		Type:      PostMeetingType,
		Props: map[string]interface{}{
			"meeting_id":        newMeetingResponse.MeetingID,
			"meeting_link":      newMeetingResponse.JoinURL,
			"meeting_personal":  req.Personal,
			"override_username": PostMeetingOverrideUsername,
			"meeting_topic":     "Meeting created by " + user.Username,
			"meeting_status":    "STARTED",
			"from_webhook":      "true",
			"override_icon_url": path.Join(*serverConfiguration.ServiceSettings.SiteURL, "plugins", manifest.ID, "api", "v1", "assets", "profile.png"),
		},
	}

	post, appErr := p.API.CreatePost(post)
	if appErr != nil {
		mlog.Error("Error creating a new post with the new meeting: " + appErr.Error())
		http.Error(w, appErr.Error(), http.StatusInternalServerError)
		return
	}

	appErr = p.API.KVSet(fmt.Sprintf("%v%v", PostMeetingKey, newMeetingResponse.MeetingID), []byte(post.Id))
	if appErr != nil {
		mlog.Error("Error writing meeting id to the database: " + appErr.Error())
		http.Error(w, appErr.Error(), http.StatusInternalServerError)
		return
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

func (p *Plugin) fetchOnlineMeetingsURL() (*ApplicationState, *APIError) {
	rootURL, apiErr := p.getRootURL()
	if apiErr != nil {
		return nil, apiErr
	}

	applicationState, apiError := p.getApplicationState(*rootURL)
	if apiError != nil {
		return nil, apiError
	}

	newApplicationResponse, err := p.client.createNewApplication(
		applicationState.ApplicationsURL,
		NewApplicationRequest{
			UserAgent:  NewApplicationUserAgent,
			Culture:    NewApplicationCulture,
			EndpointID: "123",
		},
		applicationState.Token,
	)
	if err != nil {
		return nil, &APIError{Message: "Error creating a new application: " + err.Error()}
	}

	applicationState.OnlineMeetingsURL = "https://" + applicationState.Resource + "/" + newApplicationResponse.Embedded.OnlineMeetings.OnlineMeetingsLinks.MyOnlineMeetings.Href

	return applicationState, nil
}

func (p *Plugin) getApplicationState(discoveryURL string) (*ApplicationState, *APIError) {
	config := p.getConfiguration()

	DiscoveryResponse, err := p.client.performDiscovery(discoveryURL)
	if err != nil {
		return nil, &APIError{Message: "Error performing autodiscovery: " + err.Error()}
	}

	authHeader, err := p.client.performRequestAndGetAuthHeader(DiscoveryResponse.Links.User.Href)
	if err != nil {
		return nil, &APIError{Message: "Error performing request to get authentication header: " + err.Error()}
	}

	tokenURL, apiErr := p.extractTokenURL(*authHeader)
	if apiErr != nil {
		return nil, apiErr
	}

	userResourceURL := DiscoveryResponse.Links.User.Href
	resourceName := p.extractResourceNameFromUserURL(userResourceURL)
	authResponse, err := p.authenticate(*tokenURL, resourceName, *config)
	if err != nil {
		return nil, &APIError{Message: "Error during authentication: " + err.Error()}
	}

	userResourceResponse, err := p.client.readUserResource(userResourceURL, authResponse.AccessToken)
	if err != nil {
		return nil, &APIError{Message: "Error reading user resource: " + err.Error()}
	}

	applicationsURL := userResourceResponse.Links.Applications.Href
	if applicationsURL != "" {

		applicationsResourceName := p.extractResourceNameFromApplicationsURL(applicationsURL)
		if applicationsResourceName != resourceName {
			mlog.Warn("Resource from applications url is not the same as resource name from user url")

			authHeader, err := p.client.performRequestAndGetAuthHeader(applicationsURL)
			if err != nil {
				return nil, &APIError{
					Message: "Error performing request to get authentication header from new resource: " + err.Error(),
				}
			}

			tokenURL, apiErr := p.extractTokenURL(*authHeader)
			if apiErr != nil {
				return nil, apiErr
			}

			authResponse, err = p.authenticate(*tokenURL, applicationsResourceName, *config)
			if err != nil {
				return nil, &APIError{Message: "Error during authentication in new resource: " + err.Error()}
			}
		}

		return &ApplicationState{
			ApplicationsURL: applicationsURL,
			Resource:        applicationsResourceName,
			Token:           authResponse.AccessToken,
		}, nil
	}

	if userResourceResponse.Links.Redirect.Href != "" {
		return p.getApplicationState(userResourceResponse.Links.Redirect.Href)
	}

	return nil, &APIError{
		Message: "Neither applications resource or redirect resource fetched from user resource",
	}
}

func (p *Plugin) getRootURL() (*string, *APIError) {
	rootURLBytes, appErr := p.API.KVGet(RootURLKey)
	if appErr != nil {
		return nil, &APIError{Message: "Cannot fetch the root url from the database: " + appErr.Error()}
	}

	if rootURLBytes != nil {
		rootURL := string(rootURLBytes)
		return &rootURL, nil
	}

	rootURL, err := p.determineRootURL(p.getConfiguration().Domain)
	if err != nil {
		return nil, err
	}

	_ = p.API.KVSet(RootURLKey, []byte(*rootURL))

	return rootURL, nil
}

func (p *Plugin) determineRootURL(domain string) (*string, *APIError) {
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
		}

		mlog.Warn("Error performing autodiscovery with " + o.name + " root URL: " + err.Error())
	}

	return nil, &APIError{
		Message: "Cannot determine root URL. Check if your DNS server has a lyncdiscover or lyncdiscoverinternal record.",
	}
}

func (p *Plugin) extractTokenURL(authHeader string) (*string, *APIError) {
	webTicketURLRegexMatch := regexp.MustCompile(`href=(.*?),`).FindStringSubmatch(authHeader)
	if len(webTicketURLRegexMatch) < 1 {
		return nil, &APIError{
			Message: "Cannot extract webTicket URL from WWW-AUTHENTICATE header! Full header value: " + authHeader,
		}
	}
	webTicketURL := strings.ReplaceAll(webTicketURLRegexMatch[1], "\"", "")

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

	return &webTicketURL, nil
}

func (p *Plugin) authenticate(tokenURL string, resourceName string, config configuration) (*AuthResponse, error) {
	return p.client.authenticate(tokenURL, url.Values{
		"grant_type": {"password"},
		"username":   {config.Username},
		"password":   {config.Password},
		"resource":   {resourceName},
	})
}

func (p *Plugin) extractResourceNameFromUserURL(userURL string) string {
	resourceRegex := regexp.MustCompile(`https:\/\/(.*)\/Autodiscover\/`)
	resourceRegexMatch := resourceRegex.FindStringSubmatch(userURL)
	return resourceRegexMatch[1]
}

func (p *Plugin) extractResourceNameFromApplicationsURL(applicationsURL string) string {
	resourceRegex := regexp.MustCompile(`https:\/\/(.*)\/ucwa\/`)
	resourceRegexMatch := resourceRegex.FindStringSubmatch(applicationsURL)
	return resourceRegexMatch[1]
}
