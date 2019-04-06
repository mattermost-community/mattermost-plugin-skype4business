import request from 'superagent';
import AuthenticationContext from 'adal-angular';

// workaround for the "Token renewal operation failed due to timeout" issue
// https://github.com/AzureAD/azure-activedirectory-library-for-js/issues/391#issuecomment-384784134
// eslint-disable-next-line no-underscore-dangle
AuthenticationContext.prototype._addAdalFrame = function _addAdalFrame(iframeId) {
    if (typeof iframeId === 'undefined') {
        return;
    }

    this.info('Add adal frame to document:' + iframeId);
    let adalFrame = document.getElementById(iframeId);
    const self = this;
    const handleFrameCallback = () => {
        if (adalFrame) {
            self.handleWindowCallback(adalFrame.contentWindow.location.hash);
        }
    };

    if (!adalFrame) {
        if (document.createElement && document.documentElement &&
            (window.opera || window.navigator.userAgent.indexOf('MSIE 5.0') === -1)) {
            const ifr = document.createElement('iframe');
            ifr.setAttribute('id', iframeId);
            ifr.setAttribute('aria-hidden', 'true');

            // added sandbox attribute to prevent site from reloading, you only need the token
            ifr.setAttribute('sandbox', 'allow-same-origin');
            ifr.addEventListener('load', handleFrameCallback, false);
            ifr.style.visibility = 'hidden';
            ifr.style.position = 'absolute';
            ifr.style.width = '0px';
            ifr.style.height = '0px';
            ifr.style.border = 'none';

            adalFrame = document.getElementsByTagName('body')[0].appendChild(ifr);
        } else if (document.body && document.body.insertAdjacentHTML) {
            document.body.insertAdjacentHTML(
                'beforeEnd',
                '<iframe name="' + iframeId + '" id="' + iframeId + '" style="display:none"></iframe>'
            );
        }
        if (window.frames && window.frames[iframeId]) {
            adalFrame = window.frames[iframeId];
        }
    }

    // eslint-disable-next-line consistent-return
    return adalFrame;
};

export default class Client {
    constructor() {
        this.autodiscoverServiceUrl = 'https://webdir.online.lync.com/autodiscover/autodiscoverservice.svc/root';
        this.postUrl = '/plugins/skype4business/api/v1/meetings';
        this.clientIdUrl = '/plugins/skype4business/api/v1/client_id';
    }

    createMeeting = async (channelId, personal = true, topic = '', meetingId = 0) => {
        let result;

        try {
            const meetingUrl = await this.doCreateMeeting(this.autodiscoverServiceUrl);
            result = this.sendPost(this.postUrl, {
                channel_id: channelId,
                personal,
                topic,
                meeting_id: meetingId,
                metting_url: meetingUrl,
            });
        } catch (error) {
            throw error;
        }

        return result;
    };

    getClientId = async () => {
        const response = await request.
            get(this.clientIdUrl).
            set('Accept', 'application/json');

        return response.body.client_id;
    };

    doCreateMeeting = async (autodiscoverServiceUrl) => {
        this.clientId = await this.getClientId();
        this.authContext = new AuthenticationContext({
            redirectUri: window.location.origin + '/plugins/skype4business/api/v1/popup/',
            clientId: this.clientId,
            popUp: true,
            cacheLocation: 'localStorage',
            callback: this.onUserSignedIn.bind(this),
            navigateToLoginRequestUrl: false,
        });
        await this.assureUserIsSignedIn();
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
    };

    generateUuid4 = () => {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
            // eslint-disable-next-line
            let r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    };

    getAccessTokenForResource = async (resourceName) => {
        const authContext = this.authContext;
        const self = this;

        return new Promise((resolve, reject) => {
            self.resolveIfSignedIn = resolve;

            authContext.acquireToken(resourceName, (errorDesc, token, error) => {
                if (error) {
                    authContext.acquireTokenPopup(resourceName, null, null, (errorDesc2, token2, error2) => {
                        if (error2) {
                            return reject(new Error(errorDesc2));
                        }

                        return resolve(token2);
                    });
                }

                return resolve(token);
            });
        });
    };

    assureUserIsSignedIn = async () => {
        return new Promise((resolve, reject) => {
            const user = this.authContext.getCachedUser();
            if (user) {
                resolve();
            } else {
                this.resolveIfSignedIn = resolve;
                this.rejectIfNotSigned = reject;
                this.authContext.login();
            }
        });
    };

    onUserSignedIn = (errorDesc, token, error) => {
        if (error && this.rejectIfNotSigned) {
            this.rejectIfNotSigned(new Error(errorDesc));
        } else if (this.resolveIfSignedIn) {
            this.resolveIfSignedIn(token);
        }
    };
}
