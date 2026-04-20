// Service worker — keeps the extension alive and handles any background tasks.

chrome.runtime.onInstalled.addListener(() => {
  console.log('Tunnel Dashboard extension installed.');
});
