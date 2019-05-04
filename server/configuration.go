// Copyright (c) 2017-present Mattermost, Inc. All Rights Reserved.
// See License for license information.

package main

import (
	"fmt"
	"reflect"

	"github.com/pkg/errors"
)

type configuration struct {
	IsServerVersion bool
	ClientId        string
	Username        string
	Password        string
	Domain          string
}

func (c *configuration) Clone() *configuration {
	var clone = *c
	return &clone
}

func (c *configuration) IsValid() error {

	if c.IsServerVersion {
		if c.Username == "" {
			return fmt.Errorf("Username is not configured.")
		}

		if c.Password == "" {
			return fmt.Errorf("Password is not configured.")
		}

		if c.Domain == "" {
			return fmt.Errorf("Domain is not configured.")
		}
	} else if c.ClientId == "" {
		return fmt.Errorf("ClientId is not configured")
	}

	return nil
}

func (p *Plugin) getConfiguration() *configuration {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()

	if p.configuration == nil {
		return &configuration{}
	}

	return p.configuration
}

func (p *Plugin) setConfiguration(configuration *configuration) {
	p.configurationLock.Lock()
	defer p.configurationLock.Unlock()

	if configuration != nil && p.configuration == configuration {
		// Ignore assignment if the configuration struct is empty. Go will optimize the
		// allocation for same to point at the same memory address, breaking the check
		// above.
		if reflect.ValueOf(*configuration).NumField() == 0 {
			return
		}

		panic("setConfiguration called with the existing configuration")
	}

	p.configuration = configuration
}

func (p *Plugin) OnConfigurationChange() error {
	var configuration = new(configuration)

	// Load the public configuration fields from the Mattermost server configuration.
	if err := p.API.LoadPluginConfiguration(configuration); err != nil {
		return errors.Wrap(err, "failed to load plugin configuration")
	}

	p.setConfiguration(configuration)

	return nil
}
