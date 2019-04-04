import request from 'superagent';

export default class Client {
    constructor() {
        this.autodiscoverServiceUrl = 'https://webdir.online.lync.com/autodiscover/autodiscoverservice.svc/root';
        this.redirectUrl = window.location.origin + '/plugins/skype4business/api/v1/popup/';
        this.postUrl = '/plugins/skype4business/api/v1/meetings';
        this.clientIdUrl = '/plugins/skype4business/api/v1/client_id';
    }

    createMeeting = async (channelId, personal = true, topic = '', meetingId = 0) => {
        let result;

        try {
            await this.openNewWindow();
            this.clientId = await this.getClientId();
            const meetingUrl = await this.doCreateMeeting(this.autodiscoverServiceUrl);
            this.closeWindow();
            result = this.sendPost(this.postUrl, {
                channel_id: channelId,
                personal,
                topic,
                meeting_id: meetingId,
                metting_url: meetingUrl,
            });
        } catch (error) {
            this.closeWindow();
            throw error;
        }

        return result;
    };

    openNewWindow = async () => {
        try {
            this.popupWindow = window.open(this.redirectUrl, '_blank', 'toolbar=0,location=0,menubar=0,height=510,width=480');
            if (this.popupWindow.focus) {
                this.popupWindow.focus();
            }
        } catch (error) {
            throw new Error('Allow your browser to open pop-ups on this website');
        }
    };

    closeWindow = () => {
        if (this.popupWindow) {
            this.popupWindow.close();
            this.popupWindow = null;
        }
    };

    getClientId = async () => {
        const response = await request.
            get(this.clientIdUrl).
            set('Accept', 'application/json');

        return response.body.client_id;
    };

    doCreateMeeting = async (autodiscoverServiceUrl) => {
        const applicationsResourceHref = await this.getApplicationsHref(autodiscoverServiceUrl);
        const applicationsResourceName = applicationsResourceHref.substring(0, applicationsResourceHref.indexOf('/ucwa'));

        const accessTokenToApplicationResource = await this.getAccessTokenForResource(applicationsResourceName);

        const myOnlineMeetingsHref = await this.getMyOnlineMeetingsHref(applicationsResourceHref, accessTokenToApplicationResource);

        const url = applicationsResourceName + myOnlineMeetingsHref;

        const meetingData = await this.sendMeetingData(url, accessTokenToApplicationResource);
        return meetingData;
    };

    getApplicationsHref = async (autodiscoverServiceUrl) => {
        const autodiscoverResponse = await request.
            get(autodiscoverServiceUrl).
            set('Accept', 'application/json');

        // eslint-disable-next-line no-underscore-dangle
        const userResourceHref = autodiscoverResponse.body._links.user.href;
        const userResourceName = userResourceHref.substring(0, userResourceHref.indexOf('/Autodiscover'));

        let accessTokenToUserResource = await this.getAccessTokenForResource(userResourceName);
        let authorizationValue = 'Bearer ' + accessTokenToUserResource;

        let userResourceResponse = await request.
            get(userResourceHref).
            set('Authorization', authorizationValue).
            set('Accept', 'application/json');

        if (userResourceResponse.status === 403) {
            accessTokenToUserResource = await this.getAccessTokenForResource(userResourceName);
            authorizationValue = 'Bearer ' + accessTokenToUserResource;
            userResourceResponse = await request.
                get(userResourceHref).
                set('Authorization', authorizationValue).
                set('Accept', 'application/json');
        }

        // eslint-disable-next-line no-underscore-dangle
        const links = userResourceResponse.body._links;

        if (links.applications) {
            return links.applications.href;
        } else if (links.redirect) {
            const applicationHref = await this.getApplicationsHref(links.redirect.href);
            return applicationHref;
        }

        throw new Error('Unexpected response');
    };

    getMyOnlineMeetingsHref = async (oauthAppliactionHref, accessToken) => {
        const authorizationValue = 'Bearer ' + accessToken;
        const endpointId = this.generateUuid4();

        const data = {
            UserAgent: 'mm-skype4b-plugin',
            EndpointId: endpointId,
            Culture: 'en-US',
        };
        const response = await request.
            post(oauthAppliactionHref).
            set('Authorization', authorizationValue).
            set('Accept', 'application/json').
            send(data);

        if (response.body.endpointId !== endpointId) {
            throw new Error('Endpoints don\'t match!');
        }

        // eslint-disable-next-line no-underscore-dangle
        return response.body._embedded.onlineMeetings._links.myOnlineMeetings.href;
    };

    sendMeetingData = async (url, appAccessToken) => {
        const data = {
            subject: 'Meeting created by the Mattermost Skype for Business plugin',
        };

        const response = await request.
            post(url).
            set('Authorization', 'Bearer ' + appAccessToken).
            set('Accept', 'application/json').
            send(data);

        return response.body.joinUrl;
    };

    getAccessTokenForResource = (resourceName) => {
        const secret = Math.random().toString(36).substr(2, 10);

        //removing the previous hash from the url if exists
        this.popupWindow.location.href = this.redirectUrl;
        this.popupWindow.location.href = 'https://login.microsoftonline.com/common/oauth2/authorize' +
            '?response_type=token' +
            '&client_id=' + this.clientId +
            '&redirect_uri=' + this.redirectUrl +
            '&state=' + secret +
            '&resource=' + resourceName;

        return new Promise((resolve, reject) => {
            this.interval = setInterval(() => {
                //safari
                if (this.popupWindow.location === null) {
                    clearInterval(this.interval);
                    reject(new Error('User closed the popup window!'));
                    return;
                }

                let currentHref;

                try {
                    currentHref = this.popupWindow.location.href;
                } catch (error) {
                    //Cross Domain url check error.
                    return;
                }

                //chrome
                if (!currentHref || currentHref === 'undefined') {
                    clearInterval(this.interval);
                    reject(new Error('User closed the popup window!'));
                    return;
                }

                if (currentHref.indexOf(this.redirectUrl) > -1) {
                    clearInterval(this.interval);

                    let accessToken;
                    let secretReturned;
                    let error;
                    let errorDescription;

                    for (const p of this.popupWindow.location.hash.substr(1).split('&')) {
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
                        reject(errorDescription || error);
                    } else if (secretReturned === secret) {
                        resolve(accessToken);
                    } else {
                        reject(new Error('Secrets don\t match!'));
                    }
                }
            }, 1000);
        });
    };

    sendPost = async (url, body, headers = {}) => {
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

    generateUuid4 = () => {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
            // eslint-disable-next-line
            let r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
}
