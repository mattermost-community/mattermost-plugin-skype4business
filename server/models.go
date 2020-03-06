package main

// StartMeetingRequest represents a request from S4B Online to the plugin with information about a newly created meeting.
type StartMeetingRequest struct {
	ChannelID  string `json:"channel_id"`
	Personal   bool   `json:"personal"`
	Topic      string `json:"topic"`
	MeetingID  string `json:"meeting_id"`
	MeetingURL string `json:"metting_url"`
}

// StartServerMeetingRequest represents a request from the client side to create a new meeting in S4B Server.
type StartServerMeetingRequest struct {
	ChannelID string `json:"channel_id"`
	Personal  bool   `json:"personal"`
}

// ClientIDResponse represents a response to the client side with the value of "Application ID" from the plugin settings.
type ClientIDResponse struct {
	ClientID string `json:"client_id"`
}

// ProductTypeResponse represents a response to the client side with the value of "Skype for Business Product Type" from the plugin settings.
type ProductTypeResponse struct {
	ProductType string `json:"product_type"`
}

// NewMeetingRequest represents a request to S4B Online to create a new meeting.
type NewMeetingRequest struct {
	Subject                   string `json:"subject"`
	AutomaticLeaderAssignment string `json:"automaticLeaderAssignment"`
}

// NewMeetingResponse represents a response from S4B Online with information about a newly created meeting.
type NewMeetingResponse struct {
	JoinURL   string `json:"joinUrl"`
	MeetingID string `json:"onlineMeetingId"`
}

// DiscoveryResponse represents a response from S4B Server with links to various UCWA resources.
type DiscoveryResponse struct {
	Links Links `json:"_links"`
}

// NewApplicationRequest represents a request to S4B Server to create a new application in UCWA (similar to a session).
type NewApplicationRequest struct {
	UserAgent  string `json:"UserAgent"`
	EndpointID string `json:"EndpointId"`
	Culture    string `json:"Culture"`
}

// NewApplicationResponse represents a response from S4B Server with links to resources in a newly created application.
type NewApplicationResponse struct {
	Embedded Embedded `json:"_embedded"`
}

// Embedded represents OnlineMeetings resources in a newly created application.
type Embedded struct {
	OnlineMeetings OnlineMeetings `json:"onlineMeetings"`
}

// OnlineMeetings represents an object with links related to online meetings in a newly created application.
type OnlineMeetings struct {
	OnlineMeetingsLinks OnlineMeetingsLinks `json:"_links"`
}

// OnlineMeetingsLinks represents href to MyOnlineMeetings resource in a newly created application.
type OnlineMeetingsLinks struct {
	MyOnlineMeetings Href `json:"myOnlineMeetings"`
}

// AuthResponse represents a response from S4B Server with an accessToken to a specific resource.
type AuthResponse struct {
	AccessToken string `json:"access_token"`
}

// UserResourceResponse represents a response from S4B Server with links to resources of a specific user.
type UserResourceResponse struct {
	Links Links `json:"_links"`
}

// Links represents hrefs to resources of a specific user.
type Links struct {
	User         Href `json:"user"`
	Applications Href `json:"applications"`
	Redirect     Href `json:"redirect"`
}

// Href represents an object with href to a specific UCWA resource.
type Href struct {
	Href string `json:"href"`
}

// APIError represents an error message that occurred during the work of the plugin.
type APIError struct {
	Message string
}

// ApplicationState represents data of a newly created application.
type ApplicationState struct {
	OnlineMeetingsURL string
	ApplicationsURL   string
	Resource          string
	Token             string
}
