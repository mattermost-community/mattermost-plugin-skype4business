package main

type StartMeetingRequest struct {
	ChannelID  string `json:"channel_id"`
	Personal   bool   `json:"personal"`
	Topic      string `json:"topic"`
	MeetingID  string `json:"meeting_id"`
	MeetingURL string `json:"metting_url"`
}

type StartServerMeetingRequest struct {
	ChannelID string `json:"channel_id"`
	Personal  bool   `json:"personal"`
}

type ClientIDResponse struct {
	ClientID string `json:"client_id"`
}

type ProductTypeResponse struct {
	ProductType string `json:"product_type"`
}

type State struct {
	userID string
	State  string
}

type NewMeetingRequest struct {
	Subject                   string `json:"subject"`
	AutomaticLeaderAssignment string `json:"automaticLeaderAssignment"`
}

type NewMeetingResponse struct {
	JoinURL   string `json:"joinUrl"`
	MeetingID string `json:"onlineMeetingId"`
}

type DiscoveryResponse struct {
	Links Links `json:"_links"`
}

type NewApplicationRequest struct {
	UserAgent  string `json:"UserAgent"`
	EndpointID string `json:"EndpointId"`
	Culture    string `json:"Culture"`
}

type NewApplicationResponse struct {
	Embedded Embedded `json:"_embedded"`
}

type Embedded struct {
	OnlineMeetings OnlineMeetings `json:"onlineMeetings"`
}

type OnlineMeetings struct {
	OnlineMeetingsLinks OnlineMeetingsLinks `json:"_links"`
}

type OnlineMeetingsLinks struct {
	MyOnlineMeetings Href `json:"myOnlineMeetings"`
}

type AuthResponse struct {
	AccessToken string `json:"access_token"`
}

type UserResourceResponse struct {
	Links Links `json:"_links"`
}

type Links struct {
	User         Href `json:"user"`
	Applications Href `json:"applications"`
	Redirect     Href `json:"redirect"`
}

type Href struct {
	Href string `json:"href"`
}

type APIError struct {
	Message string
}

type ApplicationState struct {
	OnlineMeetingsURL string
	ApplicationsURL   string
	Resource          string
	Token             string
}
