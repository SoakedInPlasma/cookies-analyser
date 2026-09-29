# Cookie Analyser

  A Chrome extension that reads the cookies set by any website and
  produces a plain-English security report. Built for vulnerability
  assessments and security reviews, it flags missing protections, weak
  configurations, and known tracking cookies so you can evaluate a site's
  cookie hygiene at a glance.

  ---

  ## What it checks

  - **Missing Secure flag** — cookie can be sent over plain HTTP and
  intercepted on the network
  - **Missing HttpOnly flag** — cookie is accessible to JavaScript,
  making it stealable via XSS
  - **SameSite weaknesses** — None or unset values that leave the door
  open to CSRF
  - **Excessive expiry** — cookies lasting over 1 or 2 years increase
  tracking and theft exposure
  - **Known tracker cookies** — recognises Google Analytics, Facebook
  Pixel, Hotjar, Microsoft UET, and others
  - **Third-party cookies** — flags cookies set by a domain other than
  the one you are visiting

  Each finding includes a plain-English explanation of why it matters.

  ---

  ## Setup

  Requirements: Google Chrome or any Chromium-based browser with
  extension support.

  1. Download or clone this repository
  2. Open Chrome and go to `chrome://extensions`
  3. Enable Developer mode using the toggle in the top-right corner
  4. Click Load unpacked
  5. Select the Cookie-Analyser folder
  6. The extension will appear in your toolbar. Pin it for easy access.

  ---

  ## Usage

  1. Navigate to any website
  2. Click the Cookie Analyser icon in the toolbar
  3. Each cookie is listed with its overall risk level
  4. Click the arrow next to a cookie to expand its findings
  5. Cookie names can be selected and copied directly from the list

  ---

  ## Risk levels

  | Level  | Meaning |
  |--------|---------|
  | HIGH   | Exploitable without user interaction |
  | MEDIUM | Exploitable under common attack conditions such as XSS or CSRF |     
  | LOW    | Configuration weakness or privacy concern worth noting in areport |
