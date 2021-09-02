package main

import (
	"testing"

	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/mattermost/mattermost-server/v5/plugin/plugintest"
	"github.com/stretchr/testify/assert"
)

func TestPlugin_OnConfigurationChange(t *testing.T) {
	for name, tc := range map[string]struct {
		initialDomain                          string
		returnOfLoadPluginConfiguration        error
		returnOfKVDelete                       error
		expectedErrorMessage                   string
		expectedCallsOfLoadPluginConfiguration int
		expectedCallsOfKVDelete                int
	}{
		"should load plugin configuration only": {
			initialDomain:                          "",
			returnOfLoadPluginConfiguration:        nil,
			returnOfKVDelete:                       nil,
			expectedErrorMessage:                   "",
			expectedCallsOfLoadPluginConfiguration: 1,
			expectedCallsOfKVDelete:                0,
		},
		"should delete old root URL": {
			initialDomain:                          "old domain",
			returnOfLoadPluginConfiguration:        nil,
			returnOfKVDelete:                       nil,
			expectedErrorMessage:                   "",
			expectedCallsOfLoadPluginConfiguration: 1,
			expectedCallsOfKVDelete:                1,
		},
		"should fail while loading plugin configuration": {
			initialDomain:                          "",
			returnOfLoadPluginConfiguration:        &model.AppError{Message: "test message"},
			returnOfKVDelete:                       nil,
			expectedErrorMessage:                   "failed to load plugin configuration: : test message, ",
			expectedCallsOfLoadPluginConfiguration: 1,
			expectedCallsOfKVDelete:                0,
		},
		"should fail while deleting old root URL": {
			initialDomain:                          "olddomain",
			returnOfLoadPluginConfiguration:        nil,
			returnOfKVDelete:                       &model.AppError{Message: "test message"},
			expectedErrorMessage:                   "failed to delete saved root URL in KV Store: : test message, ",
			expectedCallsOfLoadPluginConfiguration: 1,
			expectedCallsOfKVDelete:                1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			api := &plugintest.API{}
			api.On("LoadPluginConfiguration", &configuration{}).Return(tc.returnOfLoadPluginConfiguration)
			api.On("KVDelete", RootURLKey).Return(tc.returnOfKVDelete)
			p := Plugin{
				client: NewClient(),
			}
			p.setConfiguration(&configuration{Domain: tc.initialDomain})
			p.SetAPI(api)

			err := p.OnConfigurationChange()

			if tc.expectedErrorMessage != "" {
				assert.NotNil(t, err)
				assert.EqualError(t, err, tc.expectedErrorMessage)
			} else {
				assert.Nil(t, err)
			}
			api.AssertNumberOfCalls(t, "LoadPluginConfiguration", tc.expectedCallsOfLoadPluginConfiguration)
			api.AssertNumberOfCalls(t, "KVDelete", tc.expectedCallsOfKVDelete)
		})
	}
}
