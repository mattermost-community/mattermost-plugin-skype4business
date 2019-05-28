// Copyright (c) 2017-present Mattermost, Inc. All Rights Reserved.
// See License for license information.

import React from 'react';

import {makeStyleFromTheme} from 'mattermost-redux/utils/theme_utils';

export default class Icon extends React.PureComponent {
    render() {
        const style = getStyle();

        return (
            <img
                style={style.iconStyle}
                aria-hidden='true'
                src={'/plugins/skype4business/api/v1/assets/profile.png'}
            />
        );
    }
}

const getStyle = makeStyleFromTheme(() => {
    return {
        iconStyle: {
            position: 'relative',
            maxWidth: '20px',
            top: '-2px',
        },
    };
});
