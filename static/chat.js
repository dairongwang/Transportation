// Rider <-> driver chat - live, no polling, no page reload (server side: rides/chat.py).
//
// Loaded on every page of a logged-in user. Messages arrive over the stream the page already has
// open (GET /events/account, see account_live.js), which re-dispatches them as the DOM event
// "serviceuber:chat". Then:
//  * on the ride page with the chat panel (#ride-chat) for that room: the message is appended in
//    place and marked as read; sending uses fetch (POST /api/rides/<id>/chat) - the forms in the
//    panel still work without JavaScript.
//  * on any other page: a notice "💬 <name>: <text>" with a link to the chat, and unread badges
//    ([data-chat-unread-ride="<ride id>"]) count up.
// After a (re)connect the panel fetches anything it missed (GET ...?after=<last id>).
// Drafts survive the reload ride_live.js does on ride status changes (sessionStorage).
// Plain static file: the Content-Security-Policy forbids inline JS. All text is inserted with
// textContent - never as HTML.
(function () {
  var body = document.body;
  var panel = document.getElementById("ride-chat");

  // ------------------------------------------------------------------ helpers
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = text; }
    return e;
  }
  function localTime(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) { return ""; }
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  function timeEl(iso) {
    var t = el("time", "chat-time", localTime(iso));
    t.setAttribute("datetime", iso);
    t.title = new Date(iso).toLocaleString();
    return t;
  }
  function rideUrl(rideId) {
    var tpl = body.dataset.rideUrl || "/rides/0";
    return tpl.replace(/0$/, String(rideId)) + "#ride-chat";
  }
  function excerpt(text, n) { text = String(text || ""); return text.length > n ? text.slice(0, n - 1) + "…" : text; }

  function notice(text, href) {
    var box = document.getElementById("live-notices") || document.querySelector("main");
    if (!box) { return; }
    var div = el("div", "alert alert-primary alert-dismissible fade show live-notice chat-notice");
    div.setAttribute("role", "status");
    div.appendChild(document.createTextNode(text + " "));
    var a = el("a", "alert-link", "Open chat");
    a.href = href;
    div.appendChild(a);
    var btn = el("button", "btn-close");
    btn.type = "button"; btn.setAttribute("data-bs-dismiss", "alert"); btn.setAttribute("aria-label", "Close");
    div.appendChild(btn);
    box.insertBefore(div, box.firstChild);
  }

  function bumpUnread(rideId) {
    document.querySelectorAll('[data-chat-unread-ride="' + rideId + '"]').forEach(function (badge) {
      var n = (parseInt(badge.textContent, 10) || 0) + 1;
      badge.textContent = String(n);
      badge.hidden = false;
    });
  }

  // ------------------------------------------------------------------ not on a chat page
  document.addEventListener("serviceuber:chat", function (ev) {
    var d = ev.detail || {};
    var m = d.message || {};
    if (panel && String(d.chat_id) === panel.dataset.chatId) { return; }  // the panel handles it
    if (panel && String(d.ride_id) === panel.dataset.rideId) { return; }  // same ride: ride_live.js re-renders
    if (m.mine || m.sender_role === "system") { return; }
    bumpUnread(d.ride_id);
    var what = m.kind === "location" ? "shared a location" : excerpt(m.body, 80);
    notice("💬 " + (m.sender || "New message") + " (ride #" + d.ride_id + "): " + what, rideUrl(d.ride_id));
  });

  if (!panel) { return; }

  // ------------------------------------------------------------------ the chat panel
  var log = document.getElementById("chat-log");
  var form = document.getElementById("chat-form");
  var input = document.getElementById("chat-input");
  var sendBtn = document.getElementById("chat-send");
  var statusEl = document.getElementById("chat-status");
  var counter = document.getElementById("chat-count");
  var quick = document.getElementById("chat-quick");
  var locBtn = document.getElementById("chat-share-location");
  var compose = document.getElementById("chat-compose");
  var closedNote = document.getElementById("chat-closed-note");
  var stateBadge = document.getElementById("chat-state");
  var DRAFT_KEY = "chat-draft-" + panel.dataset.chatId;
  var lastId = 0;
  var readSent = 0;
  var sending = false;

  function say(text, cls) {
    if (!statusEl) { return; }
    statusEl.textContent = text || "";
    statusEl.className = "small ms-auto " + (cls || "text-muted");
  }
  function atBottom() { return log.scrollHeight - log.scrollTop - log.clientHeight < 40; }
  function scrollDown() { log.scrollTop = log.scrollHeight; }

  // Mirrors the chat_message macro in templates/rides/_chat.html.
  function renderMessage(m) {
    var row;
    if (m.sender_role === "system") {
      row = el("div", "chat-msg chat-system-row");
      var sys = el("div", "chat-system", m.body + " ");
      sys.appendChild(timeEl(m.created_at));
      row.appendChild(sys);
    } else {
      row = el("div", "chat-msg " + (m.mine ? "chat-mine" : "chat-theirs"));
      var bubble = el("div", "chat-bubble");
      var meta = el("div", "chat-meta");
      meta.appendChild(el("strong", null, m.mine ? "You" : m.sender));
      meta.appendChild(document.createTextNode(m.mine ? " · " : " · " + m.sender_role + " · "));
      meta.appendChild(timeEl(m.created_at));
      bubble.appendChild(meta);
      bubble.appendChild(el("div", "chat-body pre-wrap", m.body));
      if (m.location) {
        var loc = el("div", "chat-location", "📍 " + m.location.place + " · ");
        var a = el("a", null, Number(m.location.lat).toFixed(5) + ", " + Number(m.location.lng).toFixed(5));
        a.href = "geo:" + Number(m.location.lat).toFixed(6) + "," + Number(m.location.lng).toFixed(6);
        loc.appendChild(a);
        bubble.appendChild(loc);
      }
      row.appendChild(bubble);
    }
    row.dataset.messageId = m.id;
    return row;
  }

  function append(m) {
    if (!m || !m.id || log.querySelector('[data-message-id="' + m.id + '"]')) { return false; }
    var stick = atBottom() || m.mine;
    log.appendChild(renderMessage(m));
    lastId = Math.max(lastId, m.id);
    if (stick) { scrollDown(); }
    return true;
  }

  function setClosed(reason) {
    panel.dataset.open = "0";
    panel.classList.remove("border-success"); panel.classList.add("border-secondary");
    if (compose) { compose.remove(); compose = null; }
    if (stateBadge) { stateBadge.textContent = "closed"; stateBadge.className = "badge bg-secondary"; }
    if (closedNote) {
      closedNote.textContent = "This chat is closed" + (reason ? " (" + reason + ")" : "") + ". The conversation stays here for your reference.";
      closedNote.classList.remove("d-none");
    }
    try { sessionStorage.removeItem(DRAFT_KEY); } catch (e) { /* storage disabled */ }
  }

  function markRead() {
    if (lastId <= readSent || document.visibilityState === "hidden") { return; }
    readSent = lastId;
    fetch(panel.dataset.readUrl, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json", "X-CSRF-Token": panel.dataset.csrf },
      body: JSON.stringify({ last_id: lastId })
    }).catch(function () { readSent = 0; });
  }

  function post(payload) {
    if (sending) { return Promise.resolve(false); }
    sending = true;
    if (sendBtn) { sendBtn.disabled = true; }
    say("sending…");
    return fetch(panel.dataset.apiUrl, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json", "X-CSRF-Token": panel.dataset.csrf },
      body: JSON.stringify(payload)
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) { return { ok: r.ok, status: r.status, data: data }; });
    }).then(function (res) {
      if (!res.ok) {
        say(res.data.error || ("Could not send (HTTP " + res.status + ")."), "text-danger");
        if (res.status === 409) { setClosed(); }
        return false;
      }
      append(res.data.message);
      readSent = Math.max(readSent, res.data.message.id);
      say("");
      return true;
    }).catch(function () {
      say("Offline - message not sent. Try again.", "text-danger");
      return false;
    }).then(function (ok) {
      sending = false;
      if (sendBtn) { sendBtn.disabled = false; }
      return ok;
    });
  }

  function updateCount() { if (counter && input) { counter.textContent = String(input.value.length); } }

  // Catch up on anything pushed while the stream was (re)connecting.
  function catchUp() {
    fetch(panel.dataset.apiUrl + "?after=" + lastId, { credentials: "same-origin", cache: "no-store", headers: { "Accept": "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data || !data.chat || String(data.chat.id) !== panel.dataset.chatId) { return; }
        (data.messages || []).forEach(append);
        if (!data.chat.open && panel.dataset.open === "1") { setClosed(data.chat.close_reason); }
        markRead();
      })
      .catch(function () { /* next reconnect retries */ });
  }

  // ---- initial state: local times, scroll to the newest message
  log.querySelectorAll("[data-message-id]").forEach(function (row) { lastId = Math.max(lastId, parseInt(row.dataset.messageId, 10) || 0); });
  readSent = lastId;  // the page view marked everything read on the server
  log.querySelectorAll("time.chat-time").forEach(function (t) {
    var iso = t.getAttribute("datetime");
    t.textContent = localTime(iso) || t.textContent;
    t.title = new Date(iso).toLocaleString();
  });
  scrollDown();
  if (location.hash === "#ride-chat" && input) { input.focus(); }

  // ---- live messages for this room
  document.addEventListener("serviceuber:chat", function (ev) {
    var d = ev.detail || {};
    if (String(d.chat_id) !== panel.dataset.chatId) { return; }
    append(d.message);
    if (d.open === false && panel.dataset.open === "1") {
      var text = (d.message && d.message.body) || "";
      setClosed(text.replace(/^Chat closed: /, "").replace(/\.$/, ""));
    }
    markRead();
  });
  document.addEventListener("serviceuber:live", catchUp);
  document.addEventListener("visibilitychange", markRead);

  if (!compose || !form || !input || !window.fetch) { return; }

  // ---- composing: draft kept across reloads, Enter sends, Shift+Enter = new line
  try { input.value = sessionStorage.getItem(DRAFT_KEY) || ""; } catch (e) { /* storage disabled */ }
  updateCount();
  input.addEventListener("input", function () {
    updateCount();
    try { sessionStorage.setItem(DRAFT_KEY, input.value); } catch (e) { /* storage disabled */ }
  });
  input.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); form.requestSubmit ? form.requestSubmit() : form.dispatchEvent(new Event("submit", { cancelable: true })); }
  });
  function setDraft(text) {
    input.value = text; updateCount();
    try {
      if (text) { sessionStorage.setItem(DRAFT_KEY, text); } else { sessionStorage.removeItem(DRAFT_KEY); }
    } catch (err) { /* storage disabled */ }
  }
  // The box is cleared as soon as a message is sent, so typing can continue while it is on its
  // way; if sending fails the text comes back (unless something new was typed meanwhile).
  function sendText(text, extra) {
    setDraft("");
    var payload = extra || {};
    payload.body = text;
    return post(payload).then(function (ok) {
      if (!ok && !input.value) { setDraft(text); }
      return ok;
    });
  }
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var text = input.value.trim();
    if (!text) { say("Type a message first.", "text-danger"); return; }
    if (sending) { return; }
    sendText(text);
    input.focus();
  });

  // ---- quick replies ("I'm at the pickup point.", ...)
  if (quick) {
    quick.querySelectorAll("button[name=body]").forEach(function (btn) {
      btn.addEventListener("click", function (e) { e.preventDefault(); post({ body: btn.value }); });
    });
  }

  // ---- share my GPS position (browsers only allow it on https:// or localhost)
  if (locBtn && navigator.geolocation && window.isSecureContext) {
    locBtn.hidden = false;
    locBtn.addEventListener("click", function () {
      locBtn.disabled = true;
      say("getting your position…");
      navigator.geolocation.getCurrentPosition(function (pos) {
        // whatever is in the box goes along as the caption ("I'm by the red door")
        sendText(input.value.trim(), { lat: pos.coords.latitude, lng: pos.coords.longitude }).then(function () {
          locBtn.disabled = false;
        });
      }, function (err) {
        locBtn.disabled = false;
        say(err && err.code === 1 ? "Location permission denied." : "Could not get your position.", "text-danger");
      }, { enableHighAccuracy: true, timeout: 15000, maximumAge: 30000 });
    });
  }
})();
