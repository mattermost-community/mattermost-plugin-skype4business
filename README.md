# mattermost-plugin-skype4business

This plugin will add UI for users to start new Skype for Business meetings in a Mattermost channel. Posts are created when a meeting starts and edited when a meeting ends.

## Installation

### Skype for Business Online

1. Install the plugin
    1. Clone the project from GitHub onto your local computer and build it
    2. In Mattermost, go the System Console -> Plugins -> Management
    3. Upload the plugin
2. Register an Azure Active Directory app
    1. Go to https://portal.azure.com/#home
    2. Click Azure Active Directory -> App registrations -> New application registration
    3. Use `Mattermost Skype for Business Plugin - <your company name>` as the name
    4. Set `Accounts in any organizational directory and personal Microsoft accounts (e.g. Skype, Xbox, Outlook.com)` in `Supported account types`
    5. Under `Redirect URI (optional)` set `Web` and put "https://your-mattermost-url.com/plugins/skype4business/api/v1/popup/" replacing `https://your-mattermost-url.com` with your Mattermost URL and save
    6. Click the "Register" button to submit
3. Grant permissions for your new app
    1. Go to API permissions -> Add a permision -> Skype for Business -> Delegated permissions
    2. Check `Meetings.ReadWrite`
    3. Click "Add permissions" to submit
    4. Click "Grant admin consent for ..." and confirm
4. Allow implicit flow
    1. Click the "Manifest" button under the app name
    2. Set the "oauth2AllowImplicitFlow" and "oauth2AllowIdTokenImplicitFlow" values to true
5. Copy the "Application ID" in the "Overview" section
    1. In Mattermost, go to System Console -> Plugins -> Skype for Business
    2. Fill in the Client ID using the copied "Application ID" and save the settings.
    3. Set "Is server version?" to false
6. Enable the plugin
    1. Go to System Console -> Plugins -> Management and click "Enable" underneath the Skype For Business plugin
7. Try it out
    1. Click the Skype for Business icon in the channel header
    2. A popup will be opened to sign in on the microsoftonline.com
    3. Once you signed in, the popup will be automatically closed
    4. New post will be created with a link to the newly created meeting
    5. By clicking the "Join meeting" button, you will be redirected to a meet.lync.com page, which in turn will open a Skype for Business client installed on your computer / smartphone to join the meeting

### Skype for Business Server

1. Install the plugin
    1. Clone the project from GitHub onto your local computer and build it
    2. In Mattermost, go the System Console -> Plugins -> Management
    3. Upload the plugin
2. Create a bot account in your domain.
3. Fill the "Bot username" and "Bot password" fields with the bot's account credentials.
    1. Set "Is Server version?" to true
    2. Fill the "Domain" field with the domain where your Skype for Business Server is running, e.g. contoso.com.
4. Enable the plugin
    1. Go to System Console -> Plugins -> Management and click "Enable" underneath the Skype For Business plugin
5. Try it out
    1. Click the Skype for Business icon in the channel header
    2. New post will be created with a link to the newly created meeting
    3. By clicking the "Join meeting" button, you will be redirected to a meet.<YOUR DOMAIN> page, which in turn will open a Skype for Business client installed on your computer / smartphone to join the meeting

## Developing

This plugin contains both a server and web app portion.

Use `make dist` to build distributions of the plugin that you can upload to a Mattermost server for testing.

Use `make check-style` to check the style for the whole plugin.

### Server

Inside the `/server` directory, you will find the Go files that make up the server-side of the plugin. Within there, build the plugin like you would any other Go application.

### Web App

Inside the `/webapp` directory, you will find the JS and React files that make up the client-side of the plugin. Within there, modify files and components as necessary. Test your syntax by running `npm run build`.
