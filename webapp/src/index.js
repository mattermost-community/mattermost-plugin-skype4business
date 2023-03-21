// Copyright (c) 2017-present Mattermost, Inc. All Rights Reserved.
// See License for license information.

import React from 'react';

import {getConfig} from 'mattermost-redux/selectors/entities/general';

import {id as pluginId} from './manifest';

import Icon from './components/icon.jsx';
import PostTypeS4b from './components/post_type_s4b';
import {startMeeting} from './actions';
import {handleAuthenticationResult} from './websocket';
import {getPluginServerRoute} from './selectors';
import Reducer from './reducers';
import Client from './client';

class Plugin {
    // eslint-disable-next-line no-unused-vars
    initialize(registry, store) {
        registry.registerReducer(Reducer);
        Client.setServerRoute(getPluginServerRoute(store.getState()));

        const helpText = 'Start Skype for Business Meeting';
        const action = (channel) => {
            startMeeting(channel.id)(store.dispatch, store.getState);
        };

        // Channel header icon
        registry.registerChannelHeaderButtonAction(<Icon/>, action, helpText);

        // App Bar icon
        if (registry.registerAppBarComponent) {
            const config = getConfig(store.getState());
            const siteUrl = (config && config.SiteURL) || '';
            const iconURL = `${siteUrl}/plugins/${pluginId}/public/app-bar-icon.png`;
            registry.registerAppBarComponent(iconURL, action, helpText);
        }

        registry.registerPostTypeComponent('custom_s4b', PostTypeS4b);

        registry.registerWebSocketEventHandler('custom_' + pluginId + '_authenticated', (event) => {
            handleAuthenticationResult(store)(event.data);
        });
    }
}

window.registerPlugin(pluginId, new Plugin());
