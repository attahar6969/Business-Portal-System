# Central Business Portal

A centralized business application portal built with **Google Apps Script, HTML, CSS, and JavaScript** to organize, manage, and access multiple internal business applications through one unified interface.

The portal provides an administrator dashboard for managing application links, categories, display settings, QR codes, access codes, and administrative accounts. Its design focuses on usability, centralized control, and secure server-side authorization.

## Overview

The Business Portal acts as a central entry point for business tools used across Kisan Enterprises. Instead of maintaining and sharing multiple application links separately, administrators can manage them through a single portal.

The public interface displays available applications in an organized, searchable layout, while the administration interface provides tools to manage portal content, authentication, and security settings.

## Key Features

### 1. Centralized Application Management
- Add, edit, and delete business applications.
- Store application names, URLs, descriptions, icons, categories, and labels.
- Activate or deactivate applications without deleting their records.
- Reorder application cards to control their display sequence.
- Prevent duplicate application names and URLs.
- Manage up to 150 applications.

### 2. Application Discovery and Navigation
- Search for applications by name or related information.
- Browse applications by category.
- Display application cards in grid, list, or compact layouts.
- Open configured business tools directly from the portal.
- Support direct application opening through QR-code links where enabled.

### 3. Category Management
- Create, edit, delete, and reorder categories.
- Organize applications into groups such as Management, Sales, Finance, Human Resources, Operations, Productivity, and Reports.
- Assign applications to relevant categories for easier navigation.

### 4. QR Code Management
- Enable QR codes for supported applications.
- Generate QR-based entry points for application links.
- Configure QR-code size and display options.
- Provide QR access to active applications when QR functionality is enabled.

### 5. Portal Customization
Administrators can customize:
- Portal name, tagline, description, and footer.
- Accent colour and visual appearance.
- Application card layout.
- Default category selection.
- QR-code settings.
- Other supported display preferences.

### 6. Administrative Dashboard
The admin dashboard provides an overview of:
- Total applications.
- Active and inactive applications.
- Total categories.
- Recently updated applications.
- Storage usage and capacity information.
- Administrative activity logs.

### 7. Application Access-Code Protection
The portal supports an additional access-code gate for applications.

- Configure a portal-wide four-digit access code.
- Configure an individual access code for a specific application.
- Leave selected applications open without an additional code.
- Validate access codes on the server before releasing protected application URLs.
- Apply temporary lockouts after repeated incorrect code attempts.

This is an additional application-access control layer; it is separate from administrator authentication and from the destination application's own login system.

## Authentication and Authorization

The portal uses a dedicated administrator authentication system rather than relying solely on whether a visitor is signed in to Google.

### Administrator Sign-In
- Administrators sign in using their registered email address and password.
- The initial administrator account is established through a one-time setup code generated from the Apps Script editor.
- The initial setup code expires after 30 minutes and permits a maximum of five attempts.
- Passwords are stored as salted password hashes rather than plaintext credentials.
- Login attempts are subject to server-side protection against repeated failures.

### Session Management
After successful authentication, the server issues a session token.

- Every administrator API request validates the session token.
- Sessions expire after 30 minutes of inactivity.
- Sessions also have an eight-hour absolute lifetime.
- The portal limits the number of concurrent sessions.
- Signing out invalidates the relevant server-side session.
- Password changes invalidate other active sessions.

These controls protect administrative operations independently of the public portal interface.

### Forgot Password and Recovery
The implemented email-based password-reset flow allows an administrator to request a one-time reset code.

- Reset codes are emailed to the registered administrator address.
- Codes expire after 15 minutes.
- A maximum of five incorrect attempts is permitted per code.
- Email requests are rate-limited.
- Successful password resets invalidate active sessions.

The primary administrator can also use the Apps Script editor's restricted recovery function to reset administrator access and generate a new setup code.

### Multiple Administrator Accounts
The codebase includes support for primary and secondary administrator accounts, with invitations and role-aware sessions. Authorized administrative users can be managed through the relevant administrator functions.

The primary administrator retains responsibility for account management and privileged operations.

### Activity Logging
The portal records relevant administrative events, including:
- Successful and unsuccessful sign-in attempts.
- Administrator account creation and recovery.
- Application creation, modification, activation, deactivation, and deletion.
- Settings changes.
- Password changes and sign-outs.
- Other supported security and administrative events.

These logs help maintain visibility into changes made through the portal.

## How the System Works

1. **User opens the portal:** Google Apps Script serves the HTML interface through its web-app entry point.
2. **Portal loads application data:** Client-side JavaScript requests public application information from server-side functions.
3. **Applications are displayed:** The interface renders available applications, categories, search results, and relevant actions.
4. **Administrator signs in:** The server validates the administrator's credentials and creates a session.
5. **Administrative requests are authorized:** Each admin API call validates the session before performing its requested operation.
6. **Changes are saved:** Application records, settings, categories, authentication data, and logs are persisted in Google Apps Script Script Properties.
7. **Protected application access is checked:** Where access-code protection is enabled, the server verifies the supplied code before returning the protected destination URL.

## Technology Stack

| Technology | Purpose |
|---|---|
| Google Apps Script (V8) | Server-side logic, APIs, authentication, and data management |
| HTML5 | Portal and administration interface |
| CSS3 | Responsive layout and visual design |
| JavaScript | Client-side interaction and dynamic rendering |
| PropertiesService | Persistent application and configuration storage |
| CacheService | Temporary caching of public portal data |
| LockService | Coordinating concurrent data updates |
| MailApp | Administrator invitation and password-reset emails |

## Data Storage

The portal uses **Google Apps Script Script Properties** as its primary persistent data store. It does not use Google Sheets or an external database for its own records.

The storage layer maintains portal settings, application records, category information, administrator credentials, sessions, access-control configuration, and activity logs.

The implementation also includes storage-capacity checks and caching to support reliable operation within Apps Script platform limits.

## Deployment Configuration

The supplied `appsscript.json` configures the project as follows:

- **Runtime:** Google Apps Script V8
- **Time zone:** Asia/Kolkata
- **Execution identity:** `USER_DEPLOYING`
- **Web-app access:** `ANYONE_ANONYMOUS`

With this deployment configuration, the web app can be opened without requiring visitors to authenticate with a Google account. Administrative functions rely on the portal's own authentication and server-side authorization checks.

**Important security distinction:** Opening the portal does not automatically authorize a visitor to perform administrative actions. However, public accessibility also means the portal URL itself is not private. The security of administrator operations depends on the server-side authentication and authorization implementation.

## Security Considerations

- Keep administrator passwords and setup/reset codes confidential.
- Do not expose sensitive credentials or internal configuration in client-side code.
- Keep administrative operations behind server-side session validation.
- Review application access settings before publishing protected links.
- Remember that a code gate on the portal does not replace authentication in the destination application.
- Review the deployment's execution identity and data-access permissions before production use.

## Project Objective

The objective of this project is to simplify access to business applications, centralize link and category management, provide configurable application-level access controls, and give administrators a single interface for maintaining the organization's digital workspace.

**Project:** Kisan Enterprises Central Business Portal  
**Platform:** Google Apps Script Web Application  
**Architecture:** Serverless application with HTML/CSS/JavaScript frontend and Script Properties storage
