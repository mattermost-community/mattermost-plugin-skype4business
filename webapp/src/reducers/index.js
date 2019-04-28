import {combineReducers} from 'redux';

import ActionTypes from '../action_types';

function authenticationResult(state = false, action) {
    switch (action.type) {
    case ActionTypes.RECEIVED_AUTHENTICATION_RESULT:
        return action.data;
    default:
        return state;
    }
}

export default combineReducers({
    authenticationResult,
});