// Live background-check status for the logged-in user, on EVERY page - push, no polling, no refresh.
//
// Subscribes to GET /events/account (Server-Sent Events). The server pushes an event whenever the
// user's background check or dispute changes: the provider finished a report, a manager approved /
// rejected it, a dispute was opened, its re-check came back, the dispute was decided.
//
//  * On the background-check page the live regions ([data-live]) are re-rendered in place from a
//    fresh copy of the page. A region with data-live-key (the forms) is only replaced when the key
//    changes, so text the user is typing (e.g. a dispute explanation) is never thrown away.
//  * On any other page the user is told at once; if they just lost access they are taken to the
//    background-check page; if they just passed, the navigation unlocks without a reload.
//  * The `hello` message (also after an automatic reconnect) carries the current version, so a page
//    that missed events while offline catches up.
//  * Rider <-> driver chat messages travel on this same stream (event "chat"); they are handed to
//    static/chat.js as DOM events ("serviceuber:chat", and "serviceuber:live" on every (re)connect)
//    so a page never needs a second EventSource.
// Plain static file: the Content-Security-Policy forbids inline JS.
(function () {
  var body = document.body;
  var url = body.dataset.accountEvents;
  if (!url || !window.EventSource || !window.fetch || !window.DOMParser) { return; }
  var version = body.dataset.bgcVersion;
  var checkPage = document.querySelector('[data-live-page="background-check"]');
  var indicator = document.getElementById("live-status");

  var MESSAGES = {
    check_submitted: ["info", "Background check submitted."],
    check_completed: ["info", "Your background check result is in."],
    check_approved: ["success", "✓ A manager approved your background check."],
    check_rejected: ["danger", "Your background check was not approved."],
    dispute_opened: ["info", "Your dispute was received - a new background check has been started."],
    recheck_completed: ["info", "The new background check for your dispute is complete - a manager will now review your dispute."],
    dispute_approved: ["success", "✓ Your dispute was approved."],
    dispute_rejected: ["danger", "Your dispute was not upheld."]
  };

  function notice(text, kind, link) {
    var box = document.getElementById("live-notices") || document.querySelector("main");
    var div = document.createElement("div");
    div.className = "alert alert-" + (kind || "info") + " alert-dismissible fade show live-notice";
    div.setAttribute("role", "status");
    div.appendChild(document.createTextNode(text + " "));
    if (link) {
      var a = document.createElement("a");
      a.href = link.href; a.className = "alert-link"; a.textContent = link.text;
      div.appendChild(a);
    }
    var btn = document.createElement("button");
    btn.type = "button"; btn.className = "btn-close"; btn.setAttribute("data-bs-dismiss", "alert");
    btn.setAttribute("aria-label", "Close");
    div.appendChild(btn);
    box.insertBefore(div, box.firstChild);
  }

  function setIndicator(text, cls) {
    if (indicator) { indicator.textContent = text; indicator.className = "badge fs-6 align-middle " + cls; }
  }

  // Replace the page's live regions with their freshly rendered versions.
  function refresh(data) {
    return fetch(location.href, { credentials: "same-origin", cache: "no-store", headers: { "Accept": "text/html" } })
      .then(function (resp) {
        var here = location.pathname;
        var there = new URL(resp.url).pathname;
        if (resp.redirected && there !== here) {
          // this page is no longer available to the user (e.g. access was just revoked)
          notice((data && data.message ? data.message + " " : "") + "Taking you to the background-check page…", "warning");
          setTimeout(function () { location.assign(resp.url); }, 3500);
          return null;
        }
        return resp.text();
      })
      .then(function (html) {
        if (html === null || html === undefined) { return; }
        var doc = new DOMParser().parseFromString(html, "text/html");
        document.querySelectorAll("[data-live]").forEach(function (el) {
          var fresh = doc.querySelector('[data-live="' + el.dataset.live + '"]');
          if (!fresh) { return; }
          if (el.hasAttribute("data-live-key") && el.dataset.liveKey === fresh.dataset.liveKey) { return; }
          el.replaceWith(fresh);
        });
        var freshBody = doc.body;
        if (freshBody && freshBody.dataset.bgcVersion) { version = freshBody.dataset.bgcVersion; }
      })
      .catch(function () { /* offline: the next event or the reconnect hello will catch up */ });
  }

  function onUpdate(data, fromHello) {
    if (!data || data.version === version) { return; }
    version = data.version;
    body.dataset.bgcVersion = data.version;
    if (!fromHello) {
      var m = MESSAGES[data.reason] || ["info", "Your background-check status changed."];
      var link = null;
      if (!checkPage) { link = { href: body.dataset.bgcUrl, text: "Open the background-check page" }; }
      if (data.passed && !checkPage) { link = null; }
      notice(m[1] + (data.message ? " " + data.message : ""), m[0], link);
    }
    refresh(data);
  }

  var source = new EventSource(url, { withCredentials: true });
  source.addEventListener("hello", function (ev) {
    setIndicator("● live", "bg-success");
    onUpdate(JSON.parse(ev.data), true);  // catches up on anything missed while disconnected
  });
  source.addEventListener("background", function (ev) { onUpdate(JSON.parse(ev.data), false); });
  source.addEventListener("chat", function (ev) {
    document.dispatchEvent(new CustomEvent("serviceuber:chat", { detail: JSON.parse(ev.data) }));
  });
  source.addEventListener("open", function () {
    document.dispatchEvent(new CustomEvent("serviceuber:live", { detail: { connected: true } }));
  });
  source.onerror = function () { setIndicator("reconnecting…", "bg-secondary"); };
})();
