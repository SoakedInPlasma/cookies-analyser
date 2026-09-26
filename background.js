// listens for the extension being installed and logs a message to the console
chrome.runtime.onInstalled.addListener(() => {
  console.log("cookie analyser installed");
});