import request from 'superagent';

export default class Client {

    constructor() {
        this._autodiscoverServiceUrl = 'https://webdir.online.lync.com/autodiscover/autodiscoverservice.svc/root';
        this._redirectUrl = window.location.origin + '/plugins/skype4business/api/v1/popup/';
        this._postUrl = '/plugins/skype4business/api/v1/meetings';
        this._clientIdUrl = '/plugins/skype4business/api/v1/client_id';
    }

    createMeeting = async (channelId, personal = true, topic = '', meetingId = 0) => {

        let result;

        try {
            await this._openNewWindow();
            this._clientId = await this._getClientId();
            const meetingUrl = await this._doCreateMeeting(this._autodiscoverServiceUrl);
            this._closeWindow();
            result = this._sendPost(this._postUrl, {
                channel_id: channelId,
                personal,
                topic,
                meeting_id: meetingId,
                metting_url: meetingUrl,
            });
        } catch (error) {
            this._closeWindow();
            throw error;
        }

        return result;
    };

    _openNewWindow = async () => {
        try {
            this._popupWindow = window.open(this._redirectUrl, '_blank', 'toolbar=0,location=0,menubar=0,height=510,width=480');
            if (this._popupWindow.focus) {
                this._popupWindow.focus();
            }
        } catch (error) {
            console.log('error opening popup', error);
            throw new Error('Allow your browser to open pop-ups on this website');
        }
    };

    _closeWindow = () => {
        if (this._popupWindow) {
            this._popupWindow.close();
            this._popupWindow = undefined;
        }
    };

    _getClientId = async () => {
        const response = await request.
            get(this._clientIdUrl).
            set('Accept', 'application/json');

        return response.body.client_id;
    };

    _doCreateMeeting = async (autodiscoverServiceUrl) => {
        const applicationsResourceHref = await this._getApplicationsHref(autodiscoverServiceUrl);
        const applicationsResourceName = applicationsResourceHref.substring(0, applicationsResourceHref.indexOf('/ucwa'));

        const accessTokenToApplicationResource = await this._getAccessTokenForResource(applicationsResourceName);

        const myOnlineMeetingsHref = await this._getMyOnlineMeetingsHref(applicationsResourceHref, accessTokenToApplicationResource);

        let url = applicationsResourceName + myOnlineMeetingsHref;

        return await this._sendMeetingData(url, accessTokenToApplicationResource);
    };

    _getApplicationsHref = async (autodiscoverServiceUrl) => {

        const autodiscoverResponse = await request.
            get(autodiscoverServiceUrl).
            set('Accept', 'application/json');

        const userResourceHref = autodiscoverResponse.body._links.user.href;
        const userResourceName = userResourceHref.substring(0, userResourceHref.indexOf('/Autodiscover'));

        let accessTokenToUserResource = await this._getAccessTokenForResource(userResourceName);
        let authorizationValue = 'Bearer ' + accessTokenToUserResource;

        let userResourceResponse = await request.
            get(userResourceHref).
            set('Authorization', authorizationValue).
            set('Accept', 'application/json');

        if (userResourceResponse.status === 403) {
            accessTokenToUserResource = await this._getAccessTokenForResource(userResourceName);
            authorizationValue = 'Bearer ' + accessTokenToUserResource;
            userResourceResponse = await request.
                get(userResourceHref).
                set('Authorization', authorizationValue).
                set('Accept', 'application/json');
        }

        if (userResourceResponse.body._links.applications) {
            return userResourceResponse.body._links.applications.href;
        } else if (userResourceResponse.body._links.redirect) {
            return await this._getApplicationsHref(userResourceResponse.body._links.redirect.href);
        } else {
            throw new Error('Unexpected response');
        }
    };

    _getMyOnlineMeetingsHref = async (oauthAppliactionHref, accessToken) => {
        const authorizationValue = 'Bearer ' + accessToken;
        //todo
        const data = {
            UserAgent: 'UCWA Samples',
            EndpointId: '123',
            Culture: 'en-US',
        };
        const response = await request.
            post(oauthAppliactionHref).
            set('Authorization', authorizationValue).
            set('Accept', 'application/json').
            send(data);

        return response.body._embedded.onlineMeetings._links.myOnlineMeetings.href;
    };

    _sendMeetingData = async (url, appAccessToken) => {
        const data = {
            'subject': 'Meeting created by the Mattermost Skype for Business plugin',
        };

        const response = await request.
            post(url).
            set('Authorization', 'Bearer ' + appAccessToken).
            set('Accept', 'application/json').
            send(data);

        return response.body.joinUrl;
    };

    _getAccessTokenForResource = (resourceName) => {
        const secret = Math.random().toString(36).substr(2, 10);
        //removing the previous hash from the url if exists
        this._popupWindow.location.href = this._redirectUrl;
        this._popupWindow.location.href = 'https://login.microsoftonline.com/common/oauth2/authorize' +
            '?response_type=token' +
            '&client_id=' + this._clientId +
            '&redirect_uri=' + this._redirectUrl +
            '&state=' + secret +
            '&resource=' + resourceName;

        return new Promise((resolve, reject) => {

            this._interval = setInterval(() => {

                //safari
                if (this._popupWindow.location === null) {
                    clearInterval(this._interval);
                    reject('User closed the popup window!');
                    return;
                }

                let currentHref;

                try {
                    currentHref = this._popupWindow.location.href;
                } catch (error) {
                    //Cross Domain url check error.
                    return;
                }

                //chrome
                if (currentHref === undefined) {
                    clearInterval(this._interval);
                    reject('User closed the popup window!');
                    return;
                }

                if (currentHref.indexOf(this._redirectUrl) > -1) {
                    clearInterval(this._interval);

                    let accessToken;
                    let secretReturned;
                    let error;
                    let errorDescription;

                    for (let p of this._popupWindow.location.hash.substr(1).split('&')) {
                        if (p.indexOf('access_token=') === 0) {
                            accessToken = p.substr('access_token='.length);
                        } else if (p.indexOf('state=') === 0) {
                            secretReturned = p.substr('state='.length);
                        } else if (p.indexOf('error=') === 0) {
                            error = p.substr('error='.length);
                        } else if (p.indexOf('error_description=') === 0) {
                            errorDescription = p.substr('error_description='.length);
                        }
                    }

                    if (error) {
                        reject(errorDescription ? errorDescription : error);
                    } else if (secretReturned !== secret) {
                        reject('Secrets don\t match!');
                    } else {
                        resolve(accessToken);
                    }
                }
            }, 1000);
        });
    };

    _sendPost = async (url, body, headers = {}) => {
        headers['X-Requested-With'] = 'XMLHttpRequest';

        try {
            const response = await request.
                post(url).
                send(body).
                set(headers).
                type('application/json').
                accept('application/json');

            return response.body;
        } catch (err) {
            throw err;
        }
    }
}


