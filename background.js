chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  
  if (message.type === 'save-password') {
    handleSave(message.data)
      .then(() => sendResponse({ status: 'saved' }))
      .catch(err => sendResponse({ status: 'error', error: err.message }));
    return true; 
  }

  if (message.type === 'get-passwords') {
    handleGet()
      .then(passwords => sendResponse({ passwords }))
      .catch(err => sendResponse({ status: 'error', error: err.message }));
    return true;
  }

  if (message.type === 'update-password') {
    handleUpdate(message.data)
      .then(() => sendResponse({ status: 'updated' }))
      .catch(err => sendResponse({ status: 'error', error: err.message }));
    return true;
  }

  if (message.type === 'delete-password') {
    handleDelete(message.data)
      .then(() => sendResponse({ status: 'deleted' }))
      .catch(err => sendResponse({ status: 'error', error: err.message }));
    return true;
  }
});


async function handleSave(data) {
  const { site, username, password } = data;
  const stored = await chrome.storage.local.get(['passwords']);
  const passwords = stored.passwords || [];
  passwords.push({ site, username, password, date: new Date().toISOString() });
  await chrome.storage.local.set({ passwords });
}

async function handleGet() {
  const stored = await chrome.storage.local.get(['passwords']);
  return stored.passwords || [];
}

async function handleUpdate(data) {
  const { index, site, username, password } = data;
  const stored = await chrome.storage.local.get(['passwords']);
  const passwords = stored.passwords || [];
  if (index >= 0 && index < passwords.length) {
    passwords[index] = { site, username, password, date: new Date().toISOString() };
    await chrome.storage.local.set({ passwords });
  } else {
    throw new Error("Item not found");
  }
}

async function handleDelete(data) {
  const { index } = data;
  const stored = await chrome.storage.local.get(['passwords']);
  const passwords = stored.passwords || [];
  
  if (index >= 0 && index < passwords.length) {
    passwords.splice(index, 1); 
    await chrome.storage.local.set({ passwords });
  } else {
    throw new Error("Item not found");
  }
}