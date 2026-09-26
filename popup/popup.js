const RISK_ORDER = { high: 0, medium: 1, low: 2 };

document.addEventListener("DOMContentLoaded", async () => {
  const content = document.getElementById("content");

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  // check if the tab has a URL
  if (!tab?.url) {
    content.innerHTML = '<p class="status-msg">Cannot read cookies for this page.</p>';
    return;
  }

  // check if the URL is valid
  let url;
  try {
    url = new URL(tab.url);
  } catch {
    content.innerHTML = '<p class="status-msg">Invalid page URL.</p>';
    return;
  }

  // only allow http/https pages
  if (!["http:", "https:"].includes(url.protocol)) {
    content.innerHTML = '<p class="status-msg">Only works on http/https pages.</p>';
    return;
  }

  // get all cookies for the current tab's URL
  const cookies = await chrome.cookies.getAll({ url: tab.url });

  if (cookies.length === 0) {
    content.innerHTML = '<p class="status-msg">No cookies found.</p>';
    return;
  }

  // analyse and sort cookies by risk
  const analysed = cookies
    .map((c) => ({ cookie: c, result: analyseCookie(c, url.hostname) }))
    .sort((a, b) => RISK_ORDER[a.result.risk] - RISK_ORDER[b.result.risk]);

  document.getElementById("meta").textContent =
    `${cookies.length} cookie${cookies.length !== 1 ? "s" : ""}  ${url.hostname}`;

  const list = document.createElement("ul");
  list.className = "cookie-list";

  // create a list item for each cookie and append it to the list
  for (const { cookie, result } of analysed) {
    // create a list of findings for the cookie, if any
    const findingsHtml = result.findings.length
      ? `<ul class="findings">${result.findings.map((f) => `
          <li class="finding finding--${f.severity}">
            <span class="finding-label">${esc(f.label)}</span>
            <span class="finding-why">${esc(f.why)}</span>
          </li>`).join("")}
        </ul>`
      : "";

    const item = document.createElement("li");
    item.className = "cookie-item";
    item.innerHTML = `
      <div class="cookie-row">
        <span class="toggle">&#x25B6;</span>
        <span class="cookie-name">${esc(cookie.name) || "<em>unnamed</em>"}</span>
        <span class="risk-badge risk-badge--${result.risk}">${result.risk.toUpperCase()}</span>
      </div>
      <div class="cookie-detail">
        ${findingsHtml || '<p class="no-findings">No issues found.</p>'}
      </div>`;

    const detail = item.querySelector(".cookie-detail");
    const toggle = item.querySelector(".toggle");
    detail.style.display = "none";

    item.querySelector(".cookie-row").addEventListener("click", () => {
      const open = detail.style.display === "none";
      detail.style.display = open ? "flex" : "none";
      toggle.innerHTML = open ? "&#x25BC;" : "&#x25B6;";
    });

    list.appendChild(item);
  }

  content.appendChild(list);
});

// escape HTML special characters to prevent XSS
function esc(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}