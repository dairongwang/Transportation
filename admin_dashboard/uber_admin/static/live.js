// Live admin dashboard - push, no polling, no refresh.
//
// Subscribes to GET /events (Server-Sent Events). The dashboard's server relays ServiceUber's
// Admin API event stream: new reports, provider results, decisions by ANY manager, disputes
// opened, dispute re-checks completed, disputes decided, new user registrations. On every event:
//   * a notice says what happened (not for your own decisions - you just saw those);
//   * the page's live regions ([data-live]) are re-rendered in place from a fresh copy of the page.
//     A region with data-live-key (the decision forms) is only replaced when the key changes, so a
//     note you are typing survives - unless another manager decided in the meantime, in which case
//     the form is replaced by the decision and you are told.
// The "● live" badge shows whether the relay to ServiceUber is connected.
// Plain static file: the Content-Security-Policy forbids inline JS.
(function () {
  var body = document.body;
  var url = body.dataset.eventsUrl;
  if (!url || !window.EventSource || !window.fetch || !window.DOMParser) { return; }
  var me = body.dataset.admin;
  var indicator = document.getElementById("live-indicator");

  function who(d) { return d.actor ? " by " + d.actor : ""; }
  var LABELS = {
    check_submitted: function (d) { return ["info", "New background check from " + d.username + " (" + d.check_status + ")" + (d.check_status === "consider" ? " - needs review." : ".")]; },
    check_completed: function (d) { return ["info", "Provider finished report #" + d.check_id + " of " + d.username + ": " + d.check_status + "."]; },
    check_approved: function (d) { return ["success", "Report #" + d.check_id + " (" + d.username + ") approved" + who(d) + "."]; },
    check_rejected: function (d) { return ["warning", "Report #" + d.check_id + " (" + d.username + ") rejected" + who(d) + "."]; },
    dispute_opened: function (d) { return ["info", d.username + " opened dispute #" + d.dispute_id + " - a re-check is running."]; },
    recheck_completed: function (d) { return ["info", "The re-check for dispute #" + d.dispute_id + " (" + d.username + ") is back (" + d.check_status + ") - ready to decide."]; },
    dispute_approved: function (d) { return ["success", "Dispute #" + d.dispute_id + " (" + d.username + ") approved" + who(d) + "."]; },
    dispute_rejected: function (d) { return ["warning", "Dispute #" + d.dispute_id + " (" + d.username + ") rejected" + who(d) + "."]; },
    user_registered: function (d) { return ["info", "New user registered: " + d.username + "."]; }
  };

  function notice(text, kind) {
    var box = document.getElementById("live-notices");
    if (!box) { return; }
    var div = document.createElement("div");
    div.className = "alert alert-" + (kind || "info") + " py-2 live-notice";
    div.setAttribute("role", "status");
    div.textContent = text;
    box.insertBefore(div, box.firstChild);
    while (box.children.length > 5) { box.removeChild(box.lastChild); }
  }

  function setIndicator(status) {
    if (!indicator) { return; }
    if (status && status.connected) {
      indicator.textContent = "● live"; indicator.className = "badge bg-success me-2"; indicator.title = "Connected to ServiceUber - pages update by themselves";
    } else {
      indicator.textContent = "○ offline"; indicator.className = "badge bg-danger me-2";
      indicator.title = "Not connected to ServiceUber" + (status && status.error ? ": " + status.error : "") + " - reconnecting";
    }
  }

  var timer = null;
  function scheduleRefresh() { clearTimeout(timer); timer = setTimeout(refresh, 250); }  // coalesce bursts

  function refresh() {
    fetch(location.href, { credentials: "same-origin", cache: "no-store", headers: { "Accept": "text/html" } })
      .then(function (resp) {
        if (resp.redirected && new URL(resp.url).pathname === "/login") { location.assign(resp.url); return null; }
        return resp.text();
      })
      .then(function (html) {
        if (!html) { return; }
        var doc = new DOMParser().parseFromString(html, "text/html");
        document.querySelectorAll("[data-live]").forEach(function (el) {
          var fresh = doc.querySelector('[data-live="' + el.dataset.live + '"]');
          if (!fresh) { return; }
          if (el.hasAttribute("data-live-key")) {
            if (el.dataset.liveKey === fresh.dataset.liveKey) { return; }
            var typing = el.querySelector("textarea");
            if (typing && typing.value.trim()) { notice("This item changed while you were writing - your note could not be submitted.", "warning"); }
          }
          el.replaceWith(fresh);
        });
      })
      .catch(function () { /* the next event or the reconnect will catch up */ });
  }

  var source = new EventSource(url, { withCredentials: true });
  var helloSeen = false;
  source.addEventListener("hello", function (ev) {
    setIndicator(JSON.parse(ev.data).relay);
    if (helloSeen) { scheduleRefresh(); }  // browser reconnected: catch up
    helloSeen = true;
  });
  source.addEventListener("relay", function (ev) { setIndicator(JSON.parse(ev.data)); });
  source.addEventListener("resync", scheduleRefresh);
  // A user's financial report changed (payment, refund, ride completed, booking...): only relevant
  // on that user's page.
  source.addEventListener("transactions_changed", function (ev) {
    var d = JSON.parse(ev.data);
    var region = document.querySelector("[data-live=transactions]");
    if (!region || (d.user_ids || []).indexOf(Number(region.dataset.userId)) < 0) { return; }
    notice("New financial activity for this user - the transaction report was updated.", "info");
    scheduleRefresh();
  });
  Object.keys(LABELS).forEach(function (name) {
    source.addEventListener(name, function (ev) {
      var d = JSON.parse(ev.data);
      if (d.actor !== me) { var m = LABELS[name](d); notice(m[1], m[0]); }
      scheduleRefresh();
    });
  });
  source.onerror = function () { setIndicator({ connected: false, error: "dashboard connection lost" }); };
})();
