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

	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/mattermost/mattermost-server/v5/plugin"
	"github.com/pkg/errors"
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

	var err error
	httpStatusCode := http.StatusOK
	path := r.URL.Path
	switch path {
	case "/api/v1/product_type":
		httpStatusCode, err = p.handleProductType(w, r)
	case "/api/v1/create_meeting_in_server_version":
		httpStatusCode, err = p.handleCreateMeetingInServerVersion(w, r)
	case "/api/v1/client_id":
		httpStatusCode, err = p.handleClientID(w, r)
	case "/api/v1/auth":
		httpStatusCode, err = p.handleAuthorizeInADD(w, r)
	case "/api/v1/auth_redirect":
		httpStatusCode, err = p.completeAuthorizeInADD(w, r)
	case "/api/v1/register_meeting_from_online_version":
		httpStatusCode, err = p.handleRegisterMeetingFromOnlineVersion(w, r)
	case "/api/v1/assets/profile.png":
		httpStatusCode, err = p.handleProfileImage(w)
	default:
		http.NotFound(w, r)
	}

	if err != nil {
		p.API.LogWarn(err.Error())
		http.Error(w, err.Error(), httpStatusCode)
	}
}

func (p *Plugin) handleAuthorizeInADD(w http.ResponseWriter, r *http.Request) (int, error) {
	userID := r.URL.Query().Get("mattermost_user_id")
	if userID == "" {
		return http.StatusUnauthorized, errors.New("cannot authorize in ADD. Missing 'mattermost_user_id' param")
	}

	encodedAuthURL := r.URL.Query().Get("navigateTo")
	if encodedAuthURL == "" {
		return http.StatusBadRequest, errors.New("cannot authorize in ADD. Missing 'navigateTo' param")
	}

	authURL, err := url.QueryUnescape(encodedAuthURL)
	if err != nil {
		return http.StatusBadRequest, errors.Wrap(err, "cannot authorize in ADD. An error occurred while decoding URL")
	}

	authURLValues, err := url.ParseQuery(authURL)
	if err != nil {
		return http.StatusBadRequest, errors.Wrap(err, "cannot authorize in ADD. An error occurred while parsing URL")
	}

	state := authURLValues.Get("state")
	if state == "" {
		return http.StatusBadRequest, errors.New("cannot authorize in ADD. Missing state' param")
	}

	appErr := p.API.KVSet(state, []byte(strings.TrimSpace(userID)))
	if appErr != nil {
		return http.StatusInternalServerError, errors.Wrap(appErr, "cannot authorize in ADD. An error occurred while storing the OAuth state")
	}

	http.Redirect(w, r, authURL, http.StatusFound)
	return http.StatusOK, nil
}

func (p *Plugin) completeAuthorizeInADD(w http.ResponseWriter, r *http.Request) (int, error) {
	idToken := r.FormValue("id_token")
	if idToken == "" {
		return http.StatusBadRequest, errors.New("cannot complete authorization in ADD. Missing 'id_token' param")
	}

	state := r.FormValue("state")
	if state == "" {
		return http.StatusBadRequest, errors.New("cannot complete authorization in ADD. Missing 'state' param")
	}

	userID, err := p.API.KVGet(state)
	if err != nil {
		return http.StatusBadRequest,
			errors.Wrap(err, "cannot complete authorization in ADD. An error occurred while fetching stored state")
	}

	if userID == nil {
		return http.StatusBadRequest, errors.New("cannot complete authorization in ADD. There is no stored state")
	}

	err = p.API.KVDelete(state)
	if err != nil {
		p.API.LogWarn("An error occurred while completing authorization in ADD. Cannot delete stored state",
			"err", err)
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
	_, _ = w.Write([]byte(html))

	return http.StatusOK, nil
}

func (p *Plugin) handleClientID(w http.ResponseWriter, r *http.Request) (int, error) {
	userID := r.Header.Get("Mattermost-User-Id")
	if userID == "" {
		return http.StatusUnauthorized, errors.New("cannot fetch Client ID. Missing 'Mattermost-User-Id' header")
	}

	w.Header().Set("Content-Type", "application/json")
	config := p.getConfiguration()
	var response ClientIDResponse
	response.ClientID = config.ClientID

	if err := json.NewEncoder(w).Encode(&response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	return http.StatusOK, nil
}

func (p *Plugin) handleProductType(w http.ResponseWriter, r *http.Request) (int, error) {
	userID := r.Header.Get("Mattermost-User-Id")
	if userID == "" {
		return http.StatusUnauthorized, errors.New("cannot fetch Product Type. Missing 'Mattermost-User-Id' header")
	}

	config := p.getConfiguration()
	if config == nil {
		return http.StatusUnauthorized, errors.New("cannot fetch Product Type. Fetched configuration is empty")
	}

	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(ProductTypeResponse{
		ProductType: p.getConfiguration().ProductType,
	})
	if err != nil {
		return http.StatusInternalServerError,
			errors.Wrap(err, "cannot fetch Product Type. An error occurred while encoding the product type response")
	}

	return http.StatusOK, nil
}

func (p *Plugin) handleRegisterMeetingFromOnlineVersion(w http.ResponseWriter, r *http.Request) (int, error) {
	userID := r.Header.Get("Mattermost-User-Id")
	if userID == "" {
		return http.StatusUnauthorized, errors.New("cannot register meeting. Missing 'Mattermost-User-Id' header")
	}

	user, appErr := p.API.GetUser(userID)
	if appErr != nil {
		return appErr.StatusCode, errors.Wrap(appErr, "cannot register meeting. An error occurred while fetching user")
	}

	if user == nil {
		return http.StatusUnauthorized, errors.Errorf("cannot register meeting. User with that ID doesn't exist: %s", userID)
	}

	config := p.getConfiguration()
	if config == nil {
		return http.StatusForbidden, errors.New("cannot register meeting. Fetched configuration is empty")
	}

	if config.ProductType == productTypeServer {
		return http.StatusForbidden, errors.New("cannot register meeting. Product Type is not set as 'online'")
	}

	var req StartMeetingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return http.StatusBadRequest, errors.Wrap(err, "cannot register meeting. An error occurred while decoding JSON body")
	}

	if _, appErr = p.API.GetChannelMember(req.ChannelID, user.Id); appErr != nil {
		return http.StatusForbidden, errors.Wrap(appErr, "cannot register meeting. An error occurred while fetching channel membership")
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
			"override_icon_url": path.Join(*serverConfiguration.ServiceSettings.SiteURL, "plugins", manifest.Id, "api", "v1", "assets", "profile.png"),
		},
	}

	post, appErr = p.API.CreatePost(post)
	if appErr != nil {
		return appErr.StatusCode,
			errors.Wrap(appErr, "cannot register meeting. An error occurred while creating a post with the meeting")
	}

	if appErr = p.API.KVSet(fmt.Sprintf("%v%v", PostMeetingKey, req.MeetingID), []byte(post.Id)); appErr != nil {
		return appErr.StatusCode,
			errors.Wrap(appErr, "cannot register meeting. An error occurred while saving the meeting ID in the database")
	}

	_, _ = w.Write([]byte(fmt.Sprintf("%v", req.MeetingID)))

	return http.StatusOK, nil
}

func (p *Plugin) handleCreateMeetingInServerVersion(w http.ResponseWriter, r *http.Request) (int, error) {
	config := p.getConfiguration()
	if config.ProductType == productTypeOnline {
		return http.StatusForbidden, errors.New("Cannot create meeting. Product Type is not set as 'server'")
	}

	userID := r.Header.Get("Mattermost-User-Id")
	if userID == "" {
		return http.StatusUnauthorized, errors.New("Cannot create meeting. Missing 'Mattermost-User-Id' header")
	}

	var user *model.User
	var appError *model.AppError
	user, appError = p.API.GetUser(userID)
	if appError != nil {
		return appError.StatusCode,
			errors.Wrap(appError, "cannot create meeting. An error occurred while fetching user")
	}

	if user == nil {
		return http.StatusUnauthorized,
			errors.Errorf("cannot create meeting. User with that id doesn't exist: %s", userID)
	}

	var req StartServerMeetingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return http.StatusBadRequest,
			errors.Wrap(err, "cannot create meeting. An error occurred while decoding JSON body")
	}

	if _, err := p.API.GetChannelMember(req.ChannelID, user.Id); err != nil {
		return http.StatusForbidden,
			errors.Wrap(err, "cannot create meeting. An error occurred while fetching channel membership")
	}

	applicationState, apiErr := p.fetchOnlineMeetingsURL()
	if apiErr != nil {
		return http.StatusInternalServerError,
			errors.Errorf("cannot create meeting. An error occurred while fetching meetings resource URL: %+v", apiErr)
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
		return http.StatusInternalServerError,
			errors.Wrap(err, "cannot create meeting. An error occurred while creating a new meeting in UCWA")
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
			"override_icon_url": path.Join(*serverConfiguration.ServiceSettings.SiteURL, "plugins", manifest.Id, "api", "v1", "assets", "profile.png"),
		},
	}

	post, appErr := p.API.CreatePost(post)
	if appErr != nil {
		return http.StatusInternalServerError,
			errors.Wrap(appError, "cannot create meeting. An error occurred while creating a post with a meeting")
	}

	appErr = p.API.KVSet(fmt.Sprintf("%v%v", PostMeetingKey, newMeetingResponse.MeetingID), []byte(post.Id))
	if appErr != nil {
		return http.StatusInternalServerError,
			errors.Wrap(appError, "cannot create meeting. An error occurred while saving the meeting ID in the database")
	}

	if err := json.NewEncoder(w).Encode(&newMeetingResponse); err != nil {
		return http.StatusInternalServerError,
			errors.Wrap(err, "cannot create meeting. An error occurred while encoding the new meeting response")
	}

	return http.StatusOK, nil
}

func (p *Plugin) handleProfileImage(w http.ResponseWriter) (int, error) {
	bundlePath, err := p.API.GetBundlePath()
	if err != nil {
		return http.StatusInternalServerError,
			errors.Wrap(err, "cannot fetch profile image. An error occurred while fetching the bundle path")
	}
	img, err := os.Open(filepath.Join(bundlePath, "assets", "profile.png"))
	if err != nil {
		return http.StatusNotFound,
			errors.Wrap(err, "cannot fetch profile image. An error occurred while reading the profile image file")
	}
	defer img.Close()

	w.Header().Set("Content-Type", "image/png")
	_, _ = io.Copy(w, img)

	return http.StatusOK, nil
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

	discoveryResponse, err := p.client.performDiscovery(discoveryURL)
	if err != nil {
		return nil, &APIError{Message: "Error performing autodiscovery: " + err.Error()}
	}

	authHeader, err := p.client.performRequestAndGetAuthHeader(discoveryResponse.Links.User.Href)
	if err != nil {
		return nil, &APIError{Message: "Error performing request to get authentication header: " + err.Error()}
	}

	tokenURL, apiErr := p.extractTokenURL(*authHeader)
	if apiErr != nil {
		return nil, apiErr
	}

	userResourceURL := discoveryResponse.Links.User.Href
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
			p.API.LogWarn("Resource from applications URL is not the same as resource name from user URL")

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

		p.API.LogWarn("An error occurred while performing autodiscovery with "+o.name+" root URL",
			"err", err)
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
