document.addEventListener("DOMContentLoaded", async () => {
  const content = document.getElementById("content");

  // active tab in current window
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  // checks if tab is valid / has URL
  if (!tab?.url) {
    content.innerHTML = '<p class="status-msg">Cannot read cookies for this page.</p>';
    return;
  }

  let url;
  try {
    url = new URL(tab.url);
  } catch {
    content.innerHTML = '<p class="status-msg">Invalid page URL.</p>';
    return;
  }

  // checks if tab is http/https
  if (!["http:", "https:"].includes(url.protocol)) {
    content.innerHTML = '<p class="status-msg">Cookie Analyser only works on http/https pages.</p>';
    return;
  }

  // gets cookies from current URL using the chrome.cookies API
  const cookies = await chrome.cookies.getAll({ url: tab.url });

  if (cookies.length === 0) {
    content.innerHTML = '<p class="status-msg">No cookies found for this page.</p>';
    return;
  }

  // creates a paragraph element to display the number of cookies and the hostname
  const countEl = document.createElement("p");
  countEl.className = "cookie-count";
  countEl.textContent = `${cookies.length} cookie${cookies.length !== 1 ? "s" : ""} — ${url.hostname}`;
  content.appendChild(countEl);

  const list = document.createElement("ul");
  list.className = "cookie-list";

  // iterates through the cookies and creates a list item for each cookie
  for (const cookie of cookies) {
    const expiry = cookie.session
      ? "Session"
      : new Date(cookie.expirationDate * 1000).toLocaleDateString();

    const item = document.createElement("li");
    item.className = "cookie-item";
    item.innerHTML = `
      <div class="cookie-name">${esc(cookie.name) || "<em>unnamed</em>"}</div>
      <div class="cookie-value">${esc(trunc(cookie.value, 60))}</div>
      <div class="cookie-meta">
        <span class="tag">${esc(cookie.domain)}</span>
        ${cookie.secure        ? tag("Secure",   "good") : tag("No Secure",   "bad")}
        ${cookie.httpOnly      ? tag("HttpOnly", "good") : tag("No HttpOnly", "bad")}
        <span class="tag">SameSite: ${esc(cookie.sameSite)}</span>
        <span class="tag">Expires: ${expiry}</span>
      </div>`;
    list.appendChild(item);
  }

  content.appendChild(list);
});

// helper functions
function tag(label, modifier) {
  return `<span class="tag tag--${modifier}">${label}</span>`;
}

// escapes HTML special characters to prevent XSS attacks
function esc(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// truncates a string 
function trunc(str, max) {
  return str.length > max ? str.slice(0, max) + "…" : str;
}