# Privacy Policy for Local Password Manager

**Last Updated:** January 11, 2026

**1. Introduction**
Local Password Manager ("we," "our," or "us") is dedicated to protecting your privacy. This Privacy Policy explains how our Chrome Extension operates. **In short: We do not collect, store, or transmit your personal data.**

**2. Data Collection**
We have a strict "No-Cloud" policy.
* **No Accounts:** We do not require you to create an account.
* **No Analytics:** We do not track how you use the extension.
* **No Remote Servers:** We do not operate a backend server. Your data never leaves your device.

**3. Data Storage**
All credentials, passwords, and notes are stored locally on your device using the browser's `chrome.storage.local` API. This data is encrypted using AES-GCM encryption derived from your Master Password.
* If you uninstall the extension, your data is deleted from the browser.
* We (the developers) have no access to your Master Password or your Vault.

**4. Permissions**
The extension requires specific permissions to function:
* **Storage:** To save your encrypted vault locally.
* **ActiveTab / Scripting:** To auto-fill login forms on websites you visit. This happens locally; no website data is sent to us.
* **Clipboard:** To allow you to copy passwords to your clipboard.

**5. Third-Party Services**
* **Favicons:** To display website icons, the extension may fetch favicons from a public service (e.g., Google S2). This request contains the domain name (e.g., "google.com") but no personal information.

**6. Contact**
If you have questions about this privacy policy, you may contact the developer via the support tab on the Chrome Web Store listing.
