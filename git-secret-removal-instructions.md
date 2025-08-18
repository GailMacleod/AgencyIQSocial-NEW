# Git Secret Removal Instructions

## Critical Security Issue
The service account file `attached_assets/Pasted--type-service-account-project-id-[PROJECT_ID]-private-key-id-f4de-1753352568487_1753352568487.txt` contains sensitive credentials and must be completely removed from git history.

## Required Actions

### 1. Remove from Git History (BFG Cleaner - Recommended)
```bash
# Install BFG Cleaner (if not available, use git filter-branch below)
git clone --mirror https://github.com/GailMacleod/AgencyIQSocial.git
java -jar bfg.jar --delete-files "Pasted--type-service-account-project-id-[PROJECT_ID]-private-key-id-f4de-1753352568487_1753352568487.txt" AgencyIQSocial.git
cd AgencyIQSocial.git
git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push --force
```

### 2. Alternative: Git Filter-Branch Method
```bash
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch "attached_assets/Pasted--type-service-account-project-id-[PROJECT_ID]-private-key-id-f4de-1753352568487_1753352568487.txt"' \
  --prune-empty --tag-name-filter cat -- --all

# Clean up
rm -rf .git/refs/original/
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Force push to overwrite history
git push origin --force --all
git push origin --force --tags
```

### 3. Verify Removal
```bash
# Search for any traces of the file
git log --all --full-history -- "**/Pasted--type-service-account-project-id-[PROJECT_ID]*"

# Search for credential content patterns
git log --all -S "[PROJECT_ID]" --source --all
git log --all -S "service_account" --source --all
```

### 4. Handle GitHub Secret Scanning
- Visit: https://github.com/GailMacleod/AgencyIQSocial/security/secret-scanning/unblock-secret/30LhcXqIgHr1rt6GctTqtq5QUK1
- Follow GitHub's secret scanning resolution process
- Confirm the credential has been revoked in Google Cloud Console

### 5. Revoke Compromised Credentials
1. Go to Google Cloud Console
2. Navigate to IAM & Admin → Service Accounts
3. Find service account for project `[PROJECT_ID]`
4. Delete or regenerate all keys for the VEO service account

## Warning
- This operation rewrites git history
- All collaborators must re-clone the repository
- Force push will overwrite remote history
- Backup current state before proceeding

## Post-Cleanup Verification
After completing the removal:
1. Clone repository fresh to verify file is gone
2. Update VERTEX_AI_SERVICE_ACCOUNT_KEY secret with new credentials
3. Test VEO 3.0 functionality with new service account