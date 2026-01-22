# Google OAuth Setup for VouSSH

## Step 1: Create a Google Cloud Project
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API (or Google Identity API)

## Step 2: Configure OAuth Consent Screen
1. Navigate to "APIs & Services" > "OAuth consent screen"
2. Choose "External" user type (or "Internal" for Google Workspace)
3. Fill in required fields:
   - App name: VouSSH
   - User support email: your email
   - Developer contact: your email
4. Add scopes: `openid` and `email`
5. Add test users if in testing mode

## Step 3: Create OAuth 2.0 Credentials
1. Go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "OAuth client ID"
3. Choose "Web application"
4. Add authorized redirect URIs:
   - For HTTP: `http://localhost:8080/callback`
   - For HTTPS: `https://your-domain:8080/callback`
   - **IMPORTANT**: These must match EXACTLY what's in your config.yaml

## Step 4: Copy Credentials to config.yaml
```yaml
client_id: "YOUR_CLIENT_ID.apps.googleusercontent.com"
client_secret: "YOUR_CLIENT_SECRET"
redirect_url: "http://localhost:8080/callback"  # Must match Google Console exactly!
```

## Common Issues

### Error 401: invalid_client
- **Wrong client_id or client_secret**: Double-check for typos, extra spaces, or quotes
- **Client ID format**: Should end with `.apps.googleusercontent.com`
- **Secret not copied correctly**: Regenerate if needed

### Redirect URI mismatch
- The `redirect_url` in config.yaml must EXACTLY match one in Google Console
- Check protocol (http vs https), domain, port, and path
- If using TLS, make sure to add the HTTPS version to Google Console

### Testing
After setup, check the server logs for:
```
OAuth configured with ClientID: [first 20 chars]... (length: 72)
Using redirect URL: http://localhost:8080/callback
```

The client ID should be ~72 characters long and end with `.apps.googleusercontent.com`