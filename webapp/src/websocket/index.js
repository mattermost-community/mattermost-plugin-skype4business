import {receivedAuthenticationResult} from '../actions';

export const handleAuthenticationResult = (store) => (result) => {
    return receivedAuthenticationResult(result)(store.dispatch, store.getState);
};

