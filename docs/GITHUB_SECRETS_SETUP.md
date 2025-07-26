# GitHub Actions Secrets Setup Guide

This guide explains how to configure the required secrets for ant-quic's CI/CD pipeline.

## Required Secrets

### For Basic CI/CD

These secrets are required for core functionality:

#### `CARGO_REGISTRY_TOKEN`
- **Purpose**: Publishing releases to crates.io
- **How to obtain**:
  1. Login to [crates.io](https://crates.io)
  2. Go to Account Settings → API Tokens
  3. Create a new token with publish permissions
  4. Copy the token (it won't be shown again)
- **Required for**: Release workflow

### For Docker Builds

#### `DOCKER_USERNAME`
- **Purpose**: Docker Hub authentication
- **Value**: Your Docker Hub username
- **Required for**: Docker image builds in release workflow

#### `DOCKER_PASSWORD`
- **Purpose**: Docker Hub authentication
- **Value**: Your Docker Hub password or access token
- **How to obtain**:
  1. Login to [Docker Hub](https://hub.docker.com)
  2. Go to Account Settings → Security
  3. Create a new access token
  4. Use the token instead of your password
- **Required for**: Docker image builds in release workflow

## Optional Secrets

### For Enhanced Features

#### `DISCORD_WEBHOOK`
- **Purpose**: Send release notifications to Discord
- **How to obtain**:
  1. In Discord, go to Server Settings → Integrations
  2. Create a new webhook
  3. Copy the webhook URL
- **Format**: `https://discord.com/api/webhooks/...`
- **Required for**: Release notifications

#### `CODECOV_TOKEN`
- **Purpose**: Upload coverage reports to Codecov
- **How to obtain**:
  1. Login to [Codecov](https://codecov.io)
  2. Add your repository
  3. Copy the upload token
- **Required for**: Coverage reporting

### For Debugging

#### `ACTIONS_STEP_DEBUG`
- **Purpose**: Enable step-level debug logging
- **Value**: `true`
- **Warning**: This generates verbose logs, only enable when debugging

#### `ACTIONS_RUNNER_DEBUG`
- **Purpose**: Enable runner-level debug logging
- **Value**: `true`
- **Warning**: This generates very verbose logs, use sparingly

## Setting Up Secrets

### Via GitHub Web Interface

1. Navigate to your repository on GitHub
2. Go to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Enter the secret name (exactly as shown above)
5. Enter the secret value
6. Click **Add secret**

### Via GitHub CLI

```bash
# Install GitHub CLI
brew install gh  # macOS
# or see https://cli.github.com for other platforms

# Authenticate
gh auth login

# Add secrets
gh secret set CARGO_REGISTRY_TOKEN
gh secret set DOCKER_USERNAME
gh secret set DOCKER_PASSWORD
```

### Via API

```bash
# Using curl (replace YOUR_TOKEN and REPO_OWNER/REPO_NAME)
curl -X PUT \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/REPO_OWNER/REPO_NAME/actions/secrets/CARGO_REGISTRY_TOKEN \
  -d '{"encrypted_value":"ENCRYPTED_VALUE","key_id":"KEY_ID"}'
```

## Security Best Practices

### 1. Use Access Tokens Instead of Passwords
Always prefer access tokens over passwords:
- They can be scoped to specific permissions
- They can be revoked without changing your password
- They're easier to rotate

### 2. Rotate Secrets Regularly
Set a reminder to rotate secrets every 90 days:
- Docker tokens
- crates.io tokens
- Any API keys

### 3. Limit Secret Scope
Only add secrets that are actually needed:
- Don't add Docker credentials if you're not publishing images
- Don't add Discord webhook if you don't want notifications

### 4. Monitor Secret Usage
Check the Actions logs periodically to ensure:
- Secrets aren't being logged (they should be masked)
- Workflows using secrets are from trusted sources

### 5. Use Environment-Specific Secrets
For different environments:
```yaml
# In workflow
env:
  DEPLOY_TOKEN: ${{ github.ref == 'refs/heads/main' && secrets.PROD_TOKEN || secrets.DEV_TOKEN }}
```

## Troubleshooting

### Secret Not Found
```
Error: Input required and not supplied: token
```
**Solution**: Ensure the secret name matches exactly (case-sensitive)

### Invalid Token
```
error: failed to publish to registry at https://crates.io
```
**Solution**: 
1. Verify the token hasn't expired
2. Check token has correct permissions
3. Regenerate if necessary

### Docker Login Failed
```
Error: Error response from daemon: unauthorized
```
**Solution**:
1. Verify username is correct
2. Use access token instead of password
3. Check Docker Hub service status

### Debugging Secret Issues
```yaml
# Add to workflow to debug (remove after!)
- name: Debug secrets
  run: |
    echo "Has CARGO_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN != '' }}"
    echo "Has DOCKER_USER: ${{ secrets.DOCKER_USERNAME != '' }}"
```

## Organization Secrets

For organization-wide secrets:
1. Go to Organization Settings → Secrets
2. Choose repository access:
   - All repositories
   - Private repositories
   - Selected repositories

## Dependabot Secrets

For Dependabot to access private registries:
1. Go to Settings → Secrets → Dependabot
2. Add secrets specifically for Dependabot
3. These are separate from Actions secrets

## Secret Scanning

GitHub automatically scans for exposed secrets. If you accidentally commit a secret:
1. Revoke it immediately
2. Generate a new one
3. Update the secret in GitHub Settings
4. Enable secret scanning alerts in Security settings