document.addEventListener('DOMContentLoaded', async () => {

    // --- CONFIGURATION ---
    const SESSION_TIMEOUT = 5 * 60 * 1000; // 5 Minutes
    const CLIPBOARD_CLEAR_TIME = 60000;    // 60 Seconds (New)
    
    let activityInterval;
    let clipboardTimer; // (New) Track the auto-clear timer
    let currentCryptoKey = null;

    // Global Data
    let vaultData = [];
    let editingIndex = -1;

    // DOM Elements
    const views = {
        setup: document.getElementById('setup-view'),
        login: document.getElementById('login-view'),
        vault: document.getElementById('vault-view'),
        form: document.getElementById('form-view'),
        health: document.getElementById('health-view'),
        settings: document.getElementById('settings-view')
    };

    const nav = {
        bar: document.getElementById('main-nav'),
        vaultBtn: document.getElementById('tabVault'),
        formBtn: document.getElementById('tabForm'),
        healthBtn: document.getElementById('tabHealth'),
        settingsBtn: document.getElementById('tabSettings'),
        logoutBtn: document.getElementById('logoutBtn')
    };

    // --- 1. INITIALIZATION & SESSION ---
    await checkSession();
    checkBiometricAvailability(); 

    async function checkSession() {
        const localStore = await chrome.storage.local.get(['masterHash', 'lastActive', 'vaultSalt']);
        
        if (!localStore.masterHash) {
            showView('setup');
            return;
        }

        const sessionStore = await chrome.storage.session.get(['sessionKeyJWK']);
        const now = Date.now();
        const lastActive = localStore.lastActive || 0;
        
        if ((now - lastActive) < SESSION_TIMEOUT && sessionStore.sessionKeyJWK) {
            try {
                currentCryptoKey = await importKey(sessionStore.sessionKeyJWK);
                startSession();
                await loadVault('vault'); 
            } catch (e) {
                console.error("Session restore failed", e);
                lockVault();
            }
        } else {
            lockVault();
        }
    }

    function startSession() {
        chrome.storage.local.set({ lastActive: Date.now() });
        if (activityInterval) clearInterval(activityInterval);
        activityInterval = setInterval(async () => {
            const stored = await chrome.storage.local.get(['lastActive']);
            if (Date.now() - (stored.lastActive || 0) > SESSION_TIMEOUT) lockVault();
        }, 1000);
        document.addEventListener('click', () => chrome.storage.local.set({ lastActive: Date.now() }));
        document.addEventListener('input', () => chrome.storage.local.set({ lastActive: Date.now() }));
    }

    async function lockVault() {
        clearInterval(activityInterval);
        currentCryptoKey = null;
        vaultData = [];
        await chrome.storage.session.remove('sessionKeyJWK');
        await chrome.storage.local.remove('lastActive');
        document.getElementById('items').innerHTML = ''; 
        showView('login');
    }

    // --- 2. AUTHENTICATION HANDLERS ---
    document.getElementById('setupBtn').addEventListener('click', async () => {
        const p1 = document.getElementById('setup-pwd').value;
        const p2 = document.getElementById('setup-pwd-confirm').value;
        if (p1.length < 4 || p1 !== p2) { alert("Invalid Password"); return; }

        const salt = generateSalt();
        currentCryptoKey = await deriveKey(p1, salt);
        
        await chrome.storage.local.set({ 
            masterHash: await hashString(p1),
            vaultSalt: buffToBase64(salt)
        });

        await chrome.storage.session.set({ sessionKeyJWK: await exportKey(currentCryptoKey) });
        startSession();
        
        vaultData = [];
        await saveVault(); 
        await loadVault('vault');
    });

    document.getElementById('loginBtn').addEventListener('click', async () => {
        const pwd = document.getElementById('login-password').value;
        const localStore = await chrome.storage.local.get(['masterHash', 'vaultSalt']);
        
        if (await hashString(pwd) !== localStore.masterHash) {
            document.getElementById('login-error').classList.remove('hidden');
            return;
        }

        try {
            const salt = localStore.vaultSalt ? base64ToBuff(localStore.vaultSalt) : generateSalt();
            currentCryptoKey = await deriveKey(pwd, salt);
            await chrome.storage.session.set({ sessionKeyJWK: await exportKey(currentCryptoKey) });
            
            const enrollCheck = document.getElementById('bio-enroll-check');
            if (enrollCheck && enrollCheck.checked && !enrollCheck.classList.contains('hidden')) {
                const success = await setupBiometrics(currentCryptoKey);
                if(success) enrollCheck.checked = false; 
            }

            document.getElementById('login-error').classList.add('hidden');
            document.getElementById('login-password').value = '';
            startSession();
            await loadVault('vault');
        } catch (e) { alert("Error: " + e.message); }
    });

    // --- BIOMETRICS ---
    async function checkBiometricAvailability() {
        const stored = await chrome.storage.local.get(['biometricEnabled']);
        const loginBtn = document.getElementById('bioLoginBtn');
        const enrollContainer = document.getElementById('bio-enroll-container');
        if (stored.biometricEnabled) {
            loginBtn.classList.remove('hidden');
            if(enrollContainer) enrollContainer.classList.add('hidden');
        } else {
            loginBtn.classList.add('hidden');
            if(enrollContainer) enrollContainer.classList.remove('hidden');
        }
    }

    async function setupBiometrics(key) {
        try {
            const userId = new Uint8Array(16);
            window.crypto.getRandomValues(userId);
            const challenge = new Uint8Array(32);
            window.crypto.getRandomValues(challenge);
            await navigator.credentials.create({
                publicKey: {
                    challenge: challenge,
                    rp: { name: "Local Password Manager" },
                    user: { id: userId, name: "user@local", displayName: "Vault Owner" },
                    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
                    authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
                    timeout: 60000
                }
            });
            const jwk = await exportKey(key);
            await chrome.storage.local.set({ biometricEnabled: true, biometricKeyCache: jwk });
            alert("Biometrics Enabled for next login!");
            checkBiometricAvailability();
            return true;
        } catch (e) {
            console.error("Biometric Setup Error:", e);
            if (e.name === "NotAllowedError") alert("Setup Failed: The prompt was cancelled.");
            else if (e.name === "NotSupportedError") alert("Setup Failed: No biometric hardware found.");
            else alert("Error: " + e.message);
            return false;
        }
    }

    document.getElementById('bioLoginBtn').addEventListener('click', async () => {
        try {
            const challenge = new Uint8Array(32);
            window.crypto.getRandomValues(challenge);
            await navigator.credentials.get({ publicKey: { challenge: challenge, userVerification: "required" } });
            const stored = await chrome.storage.local.get(['biometricKeyCache']);
            if (stored.biometricKeyCache) {
                currentCryptoKey = await importKey(stored.biometricKeyCache);
                await chrome.storage.session.set({ sessionKeyJWK: stored.biometricKeyCache });
                document.getElementById('login-password').value = '';
                document.getElementById('login-error').classList.add('hidden');
                startSession();
                await loadVault('vault');
            } else { alert("Biometric key lost. Please use password to login."); }
        } catch (e) { console.error("Biometric Login Error:", e); }
    });


    // --- 3. DATA MANAGEMENT ---

    async function loadVault(targetView = 'vault') {
        try {
            const stored = await chrome.storage.local.get(['encryptedVault', 'vaultIV']);
            if (stored.encryptedVault && stored.vaultIV) {
                vaultData = await decryptVault(stored.encryptedVault, stored.vaultIV, currentCryptoKey);
            } else {
                vaultData = [];
            }
            if (targetView) showView(targetView);
            renderVault(vaultData);
            analyzeHealth(vaultData);
        } catch (e) {
            console.error("Load error", e);
            lockVault();
        }
    }

    async function saveVault() {
        try {
            if (!currentCryptoKey) throw new Error("No encryption key");
            const result = await encryptVault(vaultData, currentCryptoKey);
            await chrome.storage.local.set({ 
                encryptedVault: result.ciphertext,
                vaultIV: result.iv 
            });
            return true;
        } catch (e) {
            console.error("Save failed:", e);
            alert("Encryption failed. Data not saved.");
            return false;
        }
    }

    // --- DRAG & DROP & BACKUP ---

    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('import-file');
    const fileNameDisplay = document.getElementById('file-name');

    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => {
        if(fileInput.files.length > 0) {
            fileNameDisplay.textContent = "Selected: " + fileInput.files[0].name;
            fileNameDisplay.classList.remove('hidden');
        }
    });
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault(); e.stopPropagation();
            dropZone.classList.add('drag-active');
        }, false);
    });
    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault(); e.stopPropagation();
            dropZone.classList.remove('drag-active');
        }, false);
    });
    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            fileInput.files = files; 
            fileNameDisplay.textContent = "Selected: " + files[0].name;
            fileNameDisplay.classList.remove('hidden');
        }
    });

    document.getElementById('exportBtn').addEventListener('click', async () => {
        const password = document.getElementById('export-pwd').value;
        if(!password) { alert("Please set a password for this backup file."); return; }
        
        try {
            document.getElementById('exportBtn').innerText = "Generating...";
            const salt = generateSalt();
            const exportKey = await deriveKey(password, salt);
            const encrypted = await encryptVault(vaultData, exportKey);
            
            const backupObj = {
                data: encrypted.ciphertext,
                iv: encrypted.iv,
                salt: buffToBase64(salt),
                version: 1
            };
            
            const blob = new Blob([JSON.stringify(backupObj)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `pass-backup-${new Date().toISOString().slice(0,10)}.json`;
            a.click();
            URL.revokeObjectURL(url);
            
            document.getElementById('export-pwd').value = '';
            document.getElementById('exportBtn').innerText = "Export Encrypted Backup"; 

        } catch(e) {
            console.error(e);
            alert("Export failed: " + e.message);
            document.getElementById('exportBtn').innerText = "Export Encrypted Backup";
        }
    });

    document.getElementById('importBtn').addEventListener('click', async () => {
        const password = document.getElementById('import-pwd').value;
        if(!fileInput.files.length) { alert("Please select a file."); return; }
        if(!password) { alert("Please enter the backup password."); return; }

        const file = fileInput.files[0];
        const reader = new FileReader();

        reader.onload = async (e) => {
            try {
                const backupObj = JSON.parse(e.target.result);
                if(!backupObj.salt || !backupObj.iv || !backupObj.data) throw new Error("Invalid backup format.");

                const salt = base64ToBuff(backupObj.salt);
                const importKey = await deriveKey(password, salt);
                const importedData = await decryptVault(backupObj.data, backupObj.iv, importKey);
                if(!Array.isArray(importedData)) throw new Error("Decrypted data is not a vault.");

                let addedCount = 0;
                importedData.forEach(newItem => {
                    const exists = vaultData.some(ex => ex.site === newItem.site && ex.username === newItem.username);
                    if(!exists) { vaultData.push(newItem); addedCount++; }
                });

                await saveVault();
                alert(`Success! Restored ${addedCount} new credentials.`);
                loadVault('vault');
                
                fileInput.value = ''; 
                fileNameDisplay.textContent = '';
                fileNameDisplay.classList.add('hidden');
                document.getElementById('import-pwd').value = '';

            } catch(err) {
                console.error("Import Error:", err);
                if(err.name === "OperationError") alert("Import Failed: Incorrect Password.");
                else alert("Import Failed: " + err.message);
            }
        };
        reader.readAsText(file);
    });


    // --- 4. UI & LOGIC ---

    function renderVault(passwords) {
        const container = document.getElementById('items');
        container.innerHTML = '';
        const emptyState = document.getElementById('empty-state');
        if (passwords.length === 0) { emptyState.classList.remove('hidden'); return; } 
        else { emptyState.classList.add('hidden'); }
        
        passwords.forEach((item, index) => {
            let domain = item.site;
            try { domain = new URL(item.site.startsWith('http') ? item.site : `https://${item.site}`).hostname; } catch(e){}
            const faviconUrl = `https://www.google.com/s2/favicons?domain=${domain}&sz=64`;

            const div = document.createElement('div');
            div.className = 'vault-item';
            div.innerHTML = `
                <button class="delete-btn" data-index="${index}">&times;</button>
                <div class="item-header">
                    <img src="${faviconUrl}" class="site-icon" onerror="this.src='icon-default.png'">
                    <span class="item-site" title="${item.site}">${item.site}</span>
                </div>
                <div class="item-details">
                    <span class="item-username">${item.username}</span>
                    <div class="action-buttons">
                        <button class="mini-btn fill-btn" data-index="${index}">Fill</button>
                        <button class="mini-btn copy-btn" data-pass="${item.password}">Copy</button>
                        <button class="mini-btn edit-btn" data-index="${index}">Edit</button>
                    </div>
                </div>
            `;
            container.appendChild(div);
        });
    }

    // --- MAIN CLICK HANDLER (UPDATED FOR CLIPBOARD CLEAR) ---
    document.getElementById('items').addEventListener('click', async (e) => {
        
        // FILL
        if (e.target.classList.contains('fill-btn')) {
            const item = vaultData[parseInt(e.target.dataset.index)];
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab) {
                chrome.scripting.executeScript({
                    target: { tabId: tab.id },
                    args: [item.username, item.password],
                    func: (user, pass) => {
                        const inputs = document.querySelectorAll('input[type="password"]');
                        inputs.forEach(i => { i.value = pass; i.dispatchEvent(new Event('input', {bubbles:true})); });
                        if(inputs.length > 0) {
                            const all = Array.from(document.querySelectorAll('input:not([type="hidden"])'));
                            const idx = all.indexOf(inputs[0]);
                            if(idx > 0) {
                                const prev = all[idx-1];
                                if(prev.type==='text'||prev.type==='email') { prev.value=user; prev.dispatchEvent(new Event('input',{bubbles:true})); }
                            }
                        }
                    }
                });
            }
        }
        
        // COPY (UPDATED WITH AUTO-CLEAR)
        if (e.target.classList.contains('copy-btn')) {
            const btn = e.target;
            const password = btn.dataset.pass;
            
            // 1. Clear any pending clear action from previous copies
            if (clipboardTimer) clearTimeout(clipboardTimer);

            // 2. Write to clipboard
            navigator.clipboard.writeText(password);
            
            // 3. UI Feedback
            const originalText = btn.innerText;
            btn.innerText = "Copied!";
            btn.style.backgroundColor = "#22c55e"; // Green feedback
            
            setTimeout(() => {
                btn.innerText = originalText;
                btn.style.backgroundColor = ""; // Reset color
            }, 2000);

            // 4. Set Timer to Clear Clipboard (60s)
            clipboardTimer = setTimeout(() => {
                navigator.clipboard.writeText(""); 
                console.log("Clipboard cleared for security.");
            }, CLIPBOARD_CLEAR_TIME);
        }
        
        // EDIT
        if (e.target.classList.contains('edit-btn')) {
            loadEditForm(parseInt(e.target.dataset.index));
        }
        
        // DELETE
        if (e.target.closest('.delete-btn')) {
            if(confirm("Delete this credential?")) {
                const idx = parseInt(e.target.closest('.delete-btn').dataset.index);
                vaultData.splice(idx, 1);
                await saveVault(); 
                renderVault(vaultData);
                analyzeHealth(vaultData);
            }
        }
    });

    document.getElementById('health-items').addEventListener('click', (e) => {
        if (e.target.classList.contains('edit-btn')) {
            loadEditForm(parseInt(e.target.dataset.index));
        }
    });

    function loadEditForm(index) {
        const item = vaultData[index];
        editingIndex = index;
        document.getElementById('site').value = item.site;
        document.getElementById('username').value = item.username;
        document.getElementById('password').value = item.password;
        document.getElementById('password').dispatchEvent(new Event('input')); 
        showView('form');
        document.getElementById('saveBtn').innerText = "Update Credential";
    }

    document.getElementById('saveBtn').addEventListener('click', async () => {
        const site = document.getElementById('site').value;
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        if (!site || !password) { alert("Missing fields"); return; }
        
        const newItem = { site, username, password, date: new Date().toISOString() };
        if (editingIndex >= 0) vaultData[editingIndex] = newItem; 
        else vaultData.push(newItem); 
        
        document.getElementById('saveBtn').innerText = "Encrypting...";
        const success = await saveVault(); 
        document.getElementById('saveBtn').innerText = "Save Credential";
        
        if(success) { 
            resetForm(); 
            loadVault('vault'); 
        }
    });

    function resetForm() {
        document.getElementById('site').value = '';
        document.getElementById('username').value = '';
        document.getElementById('password').value = '';
        document.getElementById('strength-bar').style.width = '0%';
        document.getElementById('strength-text').innerText = 'Strength: N/A';
        editingIndex = -1;
        document.getElementById('saveBtn').innerText = "Save Credential";
    }

    document.getElementById('generateBtn')?.addEventListener('click', () => {
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
        let pass = "";
        for(let i=0; i<16; i++) pass += chars.charAt(Math.floor(Math.random()*chars.length));
        document.getElementById('password').value = pass;
        document.getElementById('password').dispatchEvent(new Event('input'));
    });
    
    document.getElementById('toggleVisibilityBtn')?.addEventListener('click', () => {
        const i = document.getElementById('password');
        i.type = i.type==="password"?"text":"password";
    });

    function analyzeHealth(passwords) {
        let weakCount = 0;
        let reusedCount = 0;
        const passMap = {};
        const issues = [];
        passwords.forEach((item, index) => {
            const pwd = item.password;
            let isWeak = false;
            let isReused = false;
            if (passMap[pwd]) { isReused = true; reusedCount++; } 
            else { passMap[pwd] = 1; }
            const score = calculateStrength(pwd);
            if (score < 3) { isWeak = true; weakCount++; }
            if (isWeak || isReused) issues.push({ ...item, isWeak, isReused, originalIndex: index });
        });
        let overallScore = 100;
        if (passwords.length > 0) {
            overallScore -= (weakCount * 15);
            overallScore -= (reusedCount * 10);
        } else { overallScore = 0; }
        if (overallScore < 0) overallScore = 0;
        document.getElementById('health-score').innerText = overallScore;
        document.getElementById('weak-count').innerText = weakCount;
        document.getElementById('reused-count').innerText = reusedCount;
        const container = document.getElementById('health-items');
        container.innerHTML = '';
        if (issues.length === 0) {
            document.getElementById('health-empty').classList.remove('hidden');
        } else {
            document.getElementById('health-empty').classList.add('hidden');
            issues.forEach(item => {
                const div = document.createElement('div');
                div.className = 'vault-item';
                let tags = '';
                if (item.isWeak) tags += `<span class="issue-tag tag-weak">Weak</span>`;
                if (item.isReused) tags += `<span class="issue-tag tag-reused">Reused</span>`;
                div.innerHTML = `<div class="item-header"><span class="item-site">${item.site}</span>${tags}</div><div class="item-details"><span class="item-username">${item.username}</span><div class="action-buttons"><button class="mini-btn edit-btn" data-index="${item.originalIndex}">Edit</button></div></div>`;
                container.appendChild(div);
            });
        }
    }

    function calculateStrength(pwd) {
        let score = 0;
        if (pwd.length >= 8) score++;
        if (pwd.length >= 12) score++;
        if (/[A-Z]/.test(pwd)) score++;
        if (/[0-9]/.test(pwd)) score++;
        if (/[^A-Za-z0-9]/.test(pwd)) score++;
        if (pwd.length < 6) score = 0;
        if (score > 4) score = 4;
        return score;
    }

    const pwdInput = document.getElementById('password');
    const meterBar = document.getElementById('strength-bar');
    const meterText = document.getElementById('strength-text');
    pwdInput.addEventListener('input', () => {
        const val = pwdInput.value;
        const score = calculateStrength(val);
        const colors = ['#ef4444', '#f59e0b', '#f59e0b', '#84cc16', '#22c55e'];
        const texts = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
        meterBar.style.width = ((score + 1) * 20) + '%';
        meterBar.style.backgroundColor = colors[score];
        meterText.innerText = texts[score];
        meterText.style.color = colors[score];
    });

    // --- NAV HELPERS ---
    function showView(name) {
        Object.values(views).forEach(el => el.classList.add('hidden'));
        if (name !== 'login' && name !== 'setup') nav.bar.classList.remove('hidden');
        else nav.bar.classList.add('hidden');
        views[name].classList.remove('hidden');
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active-tab'));
        if(name === 'vault') nav.vaultBtn.classList.add('active-tab');
        if(name === 'form') nav.formBtn.classList.add('active-tab');
        if(name === 'health') nav.healthBtn.classList.add('active-tab');
        if(name === 'settings') nav.settingsBtn.classList.add('active-tab');
    }

    nav.vaultBtn.addEventListener('click', () => loadVault('vault'));
    nav.formBtn.addEventListener('click', () => { showView('form'); });
    nav.healthBtn.addEventListener('click', () => { loadVault('health'); }); 
    nav.settingsBtn.addEventListener('click', () => { showView('settings'); }); 
    nav.logoutBtn.addEventListener('click', lockVault);

    // --- CRYPTO LIBRARY ---
    const PBKDF2_ITERATIONS = 100000;
    
    function buffToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    function base64ToBuff(base64) {
        const bin = atob(base64); const len = bin.length; const bytes = new Uint8Array(len);
        for (let i=0; i<len; i++) bytes[i] = bin.charCodeAt(i); return bytes;
    }
    
    function generateSalt() { return window.crypto.getRandomValues(new Uint8Array(16)); }
    async function hashString(str) {
        const buf = new TextEncoder().encode(str);
        const hashBuf = await window.crypto.subtle.digest('SHA-256', buf);
        return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    async function deriveKey(password, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
        return window.crypto.subtle.deriveKey({ name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    }
    async function encryptVault(dataObj, key) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(JSON.stringify(dataObj));
        const ciphertext = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, encoded);
        return { ciphertext: buffToBase64(ciphertext), iv: buffToBase64(iv) };
    }
    async function decryptVault(ciphertextB64, ivB64, key) {
        const ciphertext = base64ToBuff(ciphertextB64);
        const iv = base64ToBuff(ivB64);
        const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ciphertext);
        return JSON.parse(new TextDecoder().decode(decrypted));
    }
    async function exportKey(key) { return await window.crypto.subtle.exportKey("jwk", key); }
    async function importKey(jwk) { return await window.crypto.subtle.importKey("jwk", jwk, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]); }
});