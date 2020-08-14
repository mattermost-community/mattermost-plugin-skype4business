// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React from 'react';
import {shallow} from 'enzyme';

import PostTypeS4b from './post_type_s4b';

describe('components/post_type_s4b', () => {
    const baseProps = {
        creatorName: 'test creator',
        theme: {id: 'theme_id'},
        post: {
            props: {
                meeting_link: 'https://test.com',
            },
        },
    };

    it('should match snapshot without a meeting topic', () => {
        const wrapper = shallow(<PostTypeS4b {...baseProps}/>);

        baseChecks(wrapper);
        expect(wrapper.find('h1').text()).toEqual('Skype for Business Meeting');
    });

    it('should match snapshot with a meeting topic', () => {
        const props = {...baseProps};
        props.post.props.meeting_topic = 'test topic';
        const wrapper = shallow(<PostTypeS4b {...props}/>);

        baseChecks(wrapper);
        expect(wrapper.find('h1').text()).toEqual('test topic');
    });

    function baseChecks(wrapper) {
        expect(wrapper).toMatchSnapshot();
        expect(wrapper.find('div')).toHaveLength(6);
        expect(wrapper.find('div').first().prop('children')[0]).toEqual('test creator has started a meeting');
        expect(wrapper.find('div').last().text()).toEqual('JOIN MEETING');
        expect(wrapper.find('a').prop('href')).toEqual('https://test.com');
    }
});
