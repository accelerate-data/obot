# MCP Server OAuth Configuration

Some remote MCP servers require OAuth authentication with pre-registered client credentials. Unlike servers that support dynamic OAuth registration, these servers need administrators to configure a static set of OAuth credentials (Client ID and Client Secret) that all users share.

## Overview

Static OAuth allows you to:

- Connect to remote MCP servers that require pre-registered OAuth applications
- Configure one OAuth application for a catalog entry that all matching deployments share
- Manage OAuth settings through the Obot admin interface

When static OAuth is configured for a remote MCP catalog entry:

1. Administrators register an OAuth application with the provider and enter the credentials in Obot
2. Administrators can create one or more matching MCP server deployments without registering another OAuth app
3. Each user still authenticates individually through the OAuth flow using the shared client credentials

## Configuring static OAuth

### Step 1: Register an OAuth application with the provider

Before configuring Obot, you need to register an OAuth application with the service provider. The specific steps vary by provider, but generally:

1. Go to the provider's developer settings or OAuth application management page
2. Create a new OAuth application
3. Set the callback/redirect URL to: `https://<your-obot-host>/oauth/mcp/callback`
4. Note the **Client ID** and **Client Secret** provided by the service

### Step 2: Create or edit a remote MCP server

1. Navigate to **MCP Management > MCP Servers** in the Obot admin interface
2. Click **Add MCP Server** and select **Remote Server**, or edit an existing remote server
3. Enter the remote server URL
4. Click **Advanced Configuration** to reveal additional options

### Step 3: Enable static OAuth

1. In the advanced configuration section, toggle **Static OAuth** to enabled
2. Click **Save** to create or update the remote MCP server

### Step 4: Configure OAuth credentials

After saving the remote MCP server with static OAuth enabled:

1. Click **Configure OAuth Credentials** in the Static OAuth section
2. Copy the displayed **OAuth callback URL** into the provider's allowed redirect URLs if it is not already registered
3. Enter the following information:
   - **Client ID**: The client ID from your registered OAuth application
   - **Client Secret**: The client secret from your registered OAuth application
4. Click **Test Credentials** and finish the provider authorization in the window that opens
5. After Obot reports a successful test, click **Save**

Obot enables **Save** only for the exact client ID and secret that passed the test. The provider callback state, status-polling token, and one-use Save proof are independent values; the proof is returned only after successful authorization. The server returns its authoritative expiration time, and the dialog disables **Save** when that time is reached. Editing either field, closing the dialog, a denied authorization, a failed token exchange, or an expired test requires a new successful test.

Once configured, matching MCP server deployments become available to users. Each user still creates a separate OAuth grant for each deployment.

## Managing OAuth credentials

### Viewing credential status

The remote MCP server shows whether OAuth credentials are configured. When viewing a remote MCP server with static OAuth:

- If credentials are configured, you'll see the Client ID
- The Client Secret is never displayed after initial configuration

### Replacing client credentials without interrupting the active app

The Obot admin interface and API clients rotate an existing application with one replacement request. Enter and test the full replacement client ID and secret while the active application and user grants remain usable, then select **Replace Credentials**. Replacement requires the same successful exact-value test used for initial Save. Obot validates the proof, replaces the saved application, and consumes the proof in one database transaction. It then removes local user grants for every matching server and server instance while retaining the cross-process credential lock.

An invalid or expired proof leaves the active application and grants unchanged. A successful replacement retains catalog servers and access rules, but each user must authorize each deployment again. Obot does not revoke grants at the provider.

**Clear Credentials** remains a separate destructive action. Use it only when the entry should become unconfigured; matching deployments remain present but unavailable until a new tested application is saved.

### Credential API lifecycle

- Initial configuration uses `POST` on the catalog-entry or workspace credential resource. Existing credentials are not overwritten. Exact-value proof validation, credential creation, and proof consumption commit or roll back together.
- Replacement uses `PUT` on that same resource. Exact-value proof validation, credential replacement, and proof consumption commit or roll back together. Local grant cleanup follows while the same cross-process credential lock is held.
- Clear uses `DELETE`. It retains catalog servers and access rules but removes the shared application and matching local grants.

For static-required catalog entries, token writes verify the current catalog entry, server URL, client ID, and client secret under the same lock. A callback or refresh that began with an older static application cannot recreate its grant after replacement or clear. Direct non-catalog dynamic registration, including CIMD, and optional-catalog dynamic registration do not use this static-application fence.

## Example: GitHub MCP Server

This example demonstrates configuring the GitHub remote MCP server.

### Register a GitHub OAuth application

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click **OAuth Apps** > **New OAuth App**
3. Fill in the application details:
   - **Application name**: A descriptive name (e.g., "Obot MCP Integration")
   - **Homepage URL**: Your Obot instance URL
   - **Authorization callback URL**: `https://<your-obot-host>/oauth/mcp/callback`
4. Click **Register application**
5. Copy the **Client ID**
6. Click **Generate a new client secret** and copy the secret

### Configure the remote MCP server in Obot

1. Navigate to **MCP Management > MCP Servers**
2. Click **Add MCP Server** > **Remote Server**
3. Enter the server details:
   - **Name**: GitHub MCP
   - **Description**: Access GitHub repositories and features
4. Enter the URL: `https://api.githubcopilot.com/mcp`
5. Click **Advanced Configuration**
6. Toggle **Static OAuth** to enabled
7. Click **Save**

### Add OAuth credentials

1. Click **Configure OAuth Credentials**
2. Confirm the displayed OAuth callback URL is registered in the GitHub OAuth app
3. Enter:
   - **Client ID**: Your GitHub OAuth app client ID
   - **Client Secret**: Your GitHub OAuth app client secret
4. Click **Test Credentials** and authorize the app in the window that opens
5. After the test succeeds, click **Save**

Users can now add the GitHub MCP server to their projects and authenticate with their GitHub accounts.

## Visibility and access control

Remote MCP servers that require static OAuth but don't have credentials configured are hidden from non-admin users. This prevents users from seeing MCP servers they cannot actually use.

Once an administrator configures the OAuth credentials, the server becomes visible to all users with appropriate access permissions.

## Limitations

- **Composite servers**: Remote servers with static OAuth cannot be included as components in composite servers. This will be addressed in a future release.
