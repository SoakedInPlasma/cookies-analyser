// Cookie Analyser
const KNOWN_TRACKER_NAMES = [
  "_ga", "_gid", "_gat",
  "_fbp", "_fbc",
  "_hjid", "_hjSessionUser", "_hjFirstSeen",
  "__utma", "__utmb", "__utmc", "__utmz",
  "_uetsid", "_uetvid",
  "IDE", "DSID",
  "fr",
  "NID", "SID", "SSID", "SAPISID", "APISID", "HSID",
];

// analyse a cookie and return an object containing its risk level and any findings
function analyseCookie(cookie, pageHostname) {
  const findings = [];

  // check for missing security flags and other issues
  if (!cookie.secure) {
    findings.push({
      severity: "high",
      label: "Missing Secure flag",
      why: "This cookie can be transmitted over plain HTTP. Anyone on the same network (e.g. public Wi-Fi) can intercept and read it.",
    });
  }

  // check for missing HttpOnly flag
  if (!cookie.httpOnly) {
    findings.push({
      severity: "medium",
      label: "Missing HttpOnly flag",
      why: "JavaScript running on this page can access this cookie. A successful XSS attack could steal it silently.",
    });
  }

  // check for SameSite attribute issues
  if (cookie.sameSite === "no_restriction") {
    findings.push({
      severity: "medium",
      label: "SameSite=None",
      why: "Cookie is attached to all cross-site requests. Without additional CSRF protections this can be exploited by malicious third-party sites.",
    });
    // check for missing Secure flag when SameSite=None is set
  } else if (cookie.sameSite === "unspecified") {
    findings.push({
      severity: "low",
      label: "SameSite not set",
      why: "Browser behaviour varies when SameSite is absent. Explicitly setting Lax or Strict removes any ambiguity.",
    });
  }

  // check for unusually long expiry times
  if (!cookie.session && cookie.expirationDate) {
    const daysLeft = (cookie.expirationDate - Date.now() / 1000) / 86400;
    if (daysLeft > 730) {
      findings.push({
        severity: "medium",
        label: "Expires in over 2 years",
        why: "An unusually long lifetime maximises tracking exposure and extends the window in which a stolen cookie remains valid.",
      });
      // check for expiry between 1 and 2 years
    } else if (daysLeft > 365) {
      findings.push({
        severity: "low",
        label: "Expires in over 1 year",
        why: "Shorter expiry limits how long a stolen or leaked cookie stays useful.",
      });
    }
  }

  // check if the cookie is a known tracker
  const isTracker = KNOWN_TRACKER_NAMES.some(
    (t) => cookie.name === t || cookie.name.startsWith(t)
  );
  if (isTracker) {
    findings.push({
      severity: "medium",
      label: "Known tracker cookie",
      why: `"${cookie.name}" is a recognised analytics or advertising cookie used to build a profile of your browsing behaviour across sessions.`,
    });
  }

  // check if the cookie is a third-party cookie
  if (pageHostname) {
    const cookieBase = baseDomain(cookie.domain.replace(/^\./, ""));
    const pageBase = baseDomain(pageHostname);
    if (cookieBase !== pageBase) {
      findings.push({
        severity: "low",
        label: "Third-party cookie",
        why: `Set by ${cookie.domain}, not by ${pageHostname}. Third-party cookies are a primary mechanism for cross-site tracking.`,
      });
    }
  }

  // determine the overall risk level based on the findings
  const severities = findings.map((f) => f.severity);
  let risk = "low";
  if (severities.includes("high")) risk = "high";
  else if (severities.includes("medium")) risk = "medium";

  return { risk, findings };
}

// get the base domain from a hostname (e.g. "sub.example.com" -> "example.com")
function baseDomain(hostname) {
  const parts = hostname.split(".");
  return parts.length >= 2 ? parts.slice(-2).join(".") : hostname;
}
