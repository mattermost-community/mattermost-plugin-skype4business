// Copyright (c) 2017-present Mattermost, Inc. All Rights Reserved.
// See License for license information.

import {PostTypes} from 'mattermost-redux/action_types';

import ActionTypes from '../action_types';
import Selectors from '../selectors';
import Client from '../client';

export function startMeeting(channelId) {
    return async (dispatch, getState) => {
        let result = {data: true};

        const currentUserId = getState().entities.users.currentUserId;
        const creatingInProgressPost = createTemporaryPost(channelId, currentUserId, 'Creating a meeting...', dispatch);
        const getAuthenticationResult = () => Selectors.getAuthenticationResult(getState());

        try {
            await Client.createMeeting(channelId, currentUserId, getAuthenticationResult);
        } catch (error) {
            createTemporaryPost(channelId, getState, 'An error occurred during creating the meeting. Make sure your browser doesn\'t block pop-ups on this website. Otherwise please try later.', dispatch);

            result = {error};
        }

        dispatch({
            type: PostTypes.REMOVE_POST,
            data: creatingInProgressPost,
        });

        return result;
    };
}

function createTemporaryPost(channelId, userId, message, dispatch) {
    const post = {
        id: 's4bPlugin' + Date.now(),
        create_at: Date.now(),
        update_at: 0,
        edit_at: 0,
        delete_at: 0,
        is_pinned: false,
        user_id: userId,
        channel_id: channelId,
        root_id: '',
        parent_id: '',
        original_id: '',
        message,
        type: 'system_ephemeral',
        props: {},
        hashtags: '',
        pending_post_id: '',
    };

    dispatch({
        type: PostTypes.RECEIVED_POSTS,
        data: {
            order: [],
            posts: {
                [post.id]: post,
            },
        },
        channelId,
    });

    return post;
}

export function receivedAuthenticationResult(result) {
    return (dispatch) => {
        dispatch({
            type: ActionTypes.RECEIVED_AUTHENTICATION_RESULT,
            data: result,
        });
    };
}
