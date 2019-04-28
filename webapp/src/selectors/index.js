import {id as pluginId} from '../manifest';

const getPluginState = (state) => state['plugins-' + pluginId] || {};

const getAuthenticationResult = (state) => getPluginState(state).authenticationResult;

export default {
    getAuthenticationResult,
};

