import request from 'superagent';
import AuthenticationContext from 'adal-angular';

import {isDesktopApp} from '../utils/user_utils';
import {Periods} from '../constants';

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

// workaround for issues with the Desktop App
// eslint-disable-next-line no-underscore-dangle
AuthenticationContext.prototype._loginPopup = function _loginPopup(urlNavigate, resource, callback) {
    const targetUrl = this.config.popupRedirectUrl + encodeURIComponent(urlNavigate + '&response_mode=form_post');

    let popupWindow;
    if (this.config.isDesktopApp) {
        popupWindow = window.open(targetUrl, 'login', 'width=' + this.CONSTANTS.POPUP_WIDTH + ', height=' + this.CONSTANTS.POPUP_HEIGHT);
    } else {
        // eslint-disable-next-line no-underscore-dangle
        popupWindow = this._openPopup(targetUrl, 'login', this.CONSTANTS.POPUP_WIDTH, this.CONSTANTS.POPUP_HEIGHT);
    }
    const loginCallback = callback || this.callback;

    if (!this.config.isDesktopApp && popupWindow == null) {
        const error = 'Error opening popup';
        const errorDesc = 'Popup Window is null. This can happen if you are using IE';
        // eslint-disable-next-line no-underscore-dangle
        this._handlePopupError(loginCallback, resource, error, errorDesc, errorDesc);
        return;
    }

    const pollTimer = setInterval(() => {
        if (!this.config.isDesktopApp) {
            // eslint-disable-next-line no-undefined
            if (!popupWindow || popupWindow.closed || popupWindow.closed === undefined) {
                const error = 'Popup Window closed';
                const errorDesc = 'Popup Window closed by UI action/ Popup Window handle destroyed due to cross zone navigation in IE/Edge';

                if (this.isAngular) {
                    // eslint-disable-next-line no-underscore-dangle
                    this._broadcast('adal:popUpClosed', errorDesc + this.CONSTANTS.RESOURCE_DELIMETER + error);
                }

                // eslint-disable-next-line no-underscore-dangle
                this._handlePopupError(loginCallback, resource, error, errorDesc, errorDesc);
                clearInterval(pollTimer);
                return;
            }
        }

        const {token, state} = this.config.getAuthenticationResult();
        if (token) {
            // eslint-disable-next-line no-underscore-dangle
            const decodedToken = this._extractIdToken(token);

            window.localStorage.setItem(this.CONSTANTS.STORAGE.IDTOKEN, token);
            window.localStorage.setItem(this.CONSTANTS.STORAGE.STATE_LOGIN, decodedToken.upn);

            this.getCachedUser();
            this.handleWindowCallback('#access_token=' + token + '&state=' + state);

            // eslint-disable-next-line no-underscore-dangle
            this._loginInProgress = false;
            // eslint-disable-next-line no-underscore-dangle
            this._acquireTokenInProgress = false;
            // eslint-disable-next-line no-underscore-dangle
            this._openedWindows = [];

            clearInterval(pollTimer);
        }
    });

    if (this.config.isDesktopApp) {
        setTimeout(() => clearInterval(pollTimer), Periods.FIVE_MINUTES_IN_MILISECONDS);
    }
};

export default class Client {
    constructor() {
        this.autodiscoverServiceUrl = 'https://webdir.online.lync.com/autodiscover/autodiscoverservice.svc/root';
        this.registerMeetingFromOnlineVersionUrl = '/plugins/skype4business/api/v1/register_meeting_from_online_version';
        this.clientIdUrl = '/plugins/skype4business/api/v1/client_id';
        this.createMeetingInServerVersionUrl = '/plugins/skype4business/api/v1/create_meeting_in_server_version';
        this.productTypeUrl = '/plugins/skype4business/api/v1/product_type';
        this.authUrl = '/plugins/skype4business/api/v1/auth';
        this.redirectUrl = '/plugins/skype4business/api/v1/auth_redirect';
    }

    createMeeting = async (channelId, currentUserId, getAuthenticationResult, personal = true, topic = '') => {
        let isServerVersion;

        try {
            isServerVersion = await this.isServerVersion();
        } catch (error) {
            throw new Error('Cannot connect with the server. Please try again later.');
        }

        try {
            if (isServerVersion) {
                await this.doCreateMeetingInServerVersion(channelId, personal);
            } else {
                await this.doCreateMeetingInOnlineVersion(channelId, currentUserId, getAuthenticationResult, personal, topic);
            }
        } catch (error) {
            if (isServerVersion) {
                throw new Error('An error occurred when creating the meeting. Please try again later.');
            } else {
                throw new Error('An error occurred when creating the meeting. Make sure your browser doesn\'t block pop-ups on this website, then try again.');
            }
        }
    };

    getClientId = async () => {
        const response = await request.
            get(this.clientIdUrl).
            set('Accept', 'application/json');

        return response.body.client_id;
    };

    doCreateMeetingInServerVersion = async (channelId, personal) => {
        const headers = {};
        headers['X-Requested-With'] = 'XMLHttpRequest';

        const response = await request.
            post(this.createMeetingInServerVersionUrl).
            send({
                channel_id: channelId,
                personal,
            }).
            set(headers).
            type('application/json').
            accept('application/json');

        return response.body;
    };

    doCreateMeetingInOnlineVersion = async (channelId, currentUserId, getAuthenticationResult, personal, topic) => {
        const clientId = await this.getClientId();
        this.authContext = new AuthenticationContext({
            clientId,
            popUp: true,
            cacheLocation: 'localStorage',
            callback: this.onUserSignedIn.bind(this),
            navigateToLoginRequestUrl: false,
            isDesktopApp: isDesktopApp(),
            redirectUri: window.location.origin + this.redirectUrl,
            popupRedirectUrl: this.authUrl + '?mattermost_user_id=' + currentUserId + '+&navigateTo=',
            getAuthenticationResult,
        });
        await this.assureUserIsSignedIn();
        const applicationsResourceHref = await this.getApplicationsHref(this.autodiscoverServiceUrl);
        const applicationsResourceName = applicationsResourceHref.substring(0, applicationsResourceHref.indexOf('/ucwa'));

        const accessTokenToApplicationResource = await this.getAccessTokenForResource(applicationsResourceName);

        const myOnlineMeetingsHref = await this.getMyOnlineMeetingsHref(applicationsResourceHref, accessTokenToApplicationResource);

        const url = applicationsResourceName + myOnlineMeetingsHref;

        const {meetingId, meetingUrl} = await this.sendMeetingData(url, accessTokenToApplicationResource);

        this.sendPost(this.registerMeetingFromOnlineVersionUrl, {
            channel_id: channelId,
            personal,
            topic,
            meeting_id: meetingId,
            metting_url: meetingUrl,
        });
    };

    getApplicationsHref = async (autodiscoverServiceUrl) => {
        const autodiscoverResponse = await request.
            get(autodiscoverServiceUrl).
            set('Accept', 'application/json');

        // eslint-disable-next-line no-underscore-dangle
        const userResourceHref = autodiscoverResponse.body._links.user.href;
        const userResourceName = userResourceHref.substring(0, userResourceHref.indexOf('/Autodiscover'));
        const accessTokenToUserResource = await this.getAccessTokenForResource(userResourceName);
        const userResourceResponse = await request.
            get(userResourceHref).
            set('Authorization', 'Bearer ' + accessTokenToUserResource).
            set('Accept', 'application/json');

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

    getMyOnlineMeetingsHref = async (oauthApplicationHref, accessToken) => {
        const authorizationValue = 'Bearer ' + accessToken;
        const endpointId = this.generateUuid4();

        const data = {
            UserAgent: 'mm-skype4b-plugin',
            EndpointId: endpointId,
            Culture: 'en-US',
        };
        const response = await request.
            post(oauthApplicationHref).
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
            automaticLeaderAssignment: 'SameEnterprise',
        };

        const response = await request.
            post(url).
            set('Authorization', 'Bearer ' + appAccessToken).
            set('Accept', 'application/json').
            send(data);

        return {
            meetingId: response.body.onlineMeetingId,
            meetingUrl: response.body.joinUrl,
        };
    };

    sendPost = async (url, body, headers = {}) => {
        headers['X-Requested-With'] = 'XMLHttpRequest';

        const response = await request.
            post(url).
            send(body).
            set(headers).
            type('application/json').
            accept('application/json');

        return response.body;
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

    isServerVersion = async () => {
        const response = await request.
            get(this.productTypeUrl).
            set('Accept', 'application/json');

        return response.body.product_type === 'server';
    };
}
