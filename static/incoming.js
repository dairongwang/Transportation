// Live "ride requests" for drivers (dashboard / Drive page) - push, no polling, no refresh.
//
// Subscribes to GET /events/driver with EventSource (Server-Sent Events). The server pushes
// an event whenever a rider orders this driver ("offer"), withdraws/times out ("withdrawn")
// or the driver answered elsewhere ("answered"). On each event the rendered fragment is
// fetched ONCE from data-offers-url and swapped into #incoming-offers; the counter badge and
// tab title are updated and a short beep plays for new requests.
// Accept / Decline are ordinary forms inside the fragment (CSRF token included).
// Plain static file: the Content-Security-Policy forbids inline JS.
(function () {
  var box = document.getElementById("incoming-rides");
  if (!box) { return; }
  var list = document.getElementById("incoming-offers");
  var count = document.getElementById("incoming-count");
  var status = document.getElementById("incoming-status");
  var baseTitle = box.dataset.title || document.title;
  var version = box.dataset.version || "";
  var known = rememberShown();

  function rememberShown() {
    var fresh = {};
    list.querySelectorAll(".incoming-offer").forEach(function (row) { fresh[row.dataset.offerId] = true; });
    return fresh;
  }
  function say(text, cls) { if (status) { status.textContent = text; status.className = "small " + cls; } }
  function beep() {
    try {
      var Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) { return; }
      var ctx = new Ctx(), osc = ctx.createOscillator(), gain = ctx.createGain();
      osc.type = "sine"; osc.frequency.value = 880; gain.gain.value = 0.08;
      osc.connect(gain); gain.connect(ctx.destination);
      osc.start(); osc.stop(ctx.currentTime + 0.25);
    } catch (e) { /* autoplay policy: silent until the user interacted with the page */ }
  }
  function setTitle(n) {
    document.title = n > 0 ? "(" + n + ") ride request" + (n > 1 ? "s" : "") + " - " + baseTitle : baseTitle;
  }
  function tick() {
    var now = Date.now();
    list.querySelectorAll(".countdown").forEach(function (el) {
      if (!el.dataset.expires) { return; }
      var left = Math.round((new Date(el.dataset.expires).getTime() - now) / 1000);
      el.textContent = left > 0 ? left + " s" : "expired";
      el.className = "countdown " + (left <= 15 ? "text-danger fw-bold" : "");
    });
  }

  // Fetch the list once (after a push event, or after (re)connecting in case something was missed).
  function refresh() {
    fetch(box.dataset.offersUrl, { headers: { "Accept": "application/json" }, credentials: "same-origin" })
      .then(function (r) { if (!r.ok) { throw new Error(r.status); } return r.json(); })
      .then(function (data) {
        if (count) { count.textContent = data.count; }
        setTitle(data.count);
        if (data.version === version) { return; }
        version = data.version;
        list.innerHTML = data.html;
        var fresh = rememberShown();
        var isNew = Object.keys(fresh).some(function (id) { return !known[id]; });
        known = fresh;
        if (isNew) {
          beep();
          list.querySelectorAll(".incoming-offer").forEach(function (row) { row.classList.add("offer-new"); });
          setTimeout(function () {
            list.querySelectorAll(".offer-new").forEach(function (row) { row.classList.remove("offer-new"); });
          }, 3000);
        }
        tick();
      })
      .catch(function () { say("could not load requests - retrying on next event", "text-danger"); });
  }

  tick();
  setInterval(tick, 1000);  // local countdown only; no network

  if (!window.EventSource) {
    say("live updates unsupported in this browser - reload to see new requests", "text-warning");
    return;
  }
  var source = new EventSource(box.dataset.eventsUrl, { withCredentials: true });
  source.addEventListener("hello", function (ev) {
    say("live", "text-success");
    var hello = JSON.parse(ev.data);
    if (hello.version !== version) { refresh(); }  // something happened while we were disconnected
  });
  ["offer", "withdrawn", "answered"].forEach(function (name) {
    source.addEventListener(name, function () { refresh(); });
  });
  source.onerror = function () { say("reconnecting…", "text-warning"); };  // EventSource retries by itself
})();
