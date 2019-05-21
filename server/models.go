package main

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

type ProductTypeResponse struct {
	ProductType string `json:"product_type"`
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
	Links Links `json:"_links"`
}

type NewApplicationRequest struct {
	UserAgent  string `json:"UserAgent"`
	EndpointId string `json:"EndpointId"`
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
	Access_token string
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
	OnlineMeetingsUrl string
	ApplicationsUrl   string
	Resource          string
	Token             string
}
