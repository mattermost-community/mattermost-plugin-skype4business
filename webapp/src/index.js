// Copyright (c) 2017-present Mattermost, Inc. All Rights Reserved.
// See License for license information.

import React from 'react';

import {id as pluginId} from './manifest';

import Icon from './components/icon.jsx';
import PostTypeS4b from './components/post_type_s4b';
import {startMeeting} from './actions';

class Plugin {
  // eslint-disable-next-line no-unused-vars
  initialize(registry, store) {
    registry.registerChannelHeaderButtonAction(
    <Icon/>,
      (channel) => {
        startMeeting(channel.id)(store.dispatch, store.getState);
      },
      'Start Skype for Business Meeting'
  );
    registry.registerPostTypeComponent('custom_s4b', PostTypeS4b);
  }
}

window.registerPlugin(pluginId, new Plugin());
