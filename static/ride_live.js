// Live ride page for riders (and drivers on their ride): push, no polling, no refresh.
//
// Subscribes to GET /events/rides/<id> (Server-Sent Events). When the driver declines, the
// offer times out, the driver accepts / starts / completes, or the ride is cancelled, a banner
// tells the rider right away and the page re-renders (reload; the banner survives it via
// sessionStorage). Plain static file: the Content-Security-Policy forbids inline JS.
(function () {
  var page = document.getElementById("ride-page");
  if (!page) { return; }
  var NOTICE_KEY = "ride-notice-" + page.dataset.rideId;

  function banner(text, cls) {
    var main = document.querySelector("main");
    var div = document.createElement("div");
    div.className = "alert alert-" + (cls || "info") + " alert-dismissible fade show";
    div.setAttribute("role", "alert");
    div.textContent = text;
    var btn = document.createElement("button");
    btn.type = "button"; btn.className = "btn-close"; btn.setAttribute("data-bs-dismiss", "alert");
    div.appendChild(btn);
    main.insertBefore(div, main.firstChild);
  }

  // a notice saved before the reload caused by the previous event
  var saved = sessionStorage.getItem(NOTICE_KEY);
  if (saved) {
    sessionStorage.removeItem(NOTICE_KEY);
    var parts = saved.split("\t");
    banner(parts[1], parts[0]);
  }

  var MESSAGES = {
    declined: function (d) { return ["warning", (d.driver || "The driver") + " declined your request. Please select another driver from the list."]; },
    expired: function (d) { return ["warning", (d.driver || "The driver") + " did not answer in time. Please select another driver."]; },
    offered: function (d) { return ["info", "Request sent to " + (d.driver || "the driver") + ". Waiting for the answer…"]; },
    accepted: function (d) { return ["success", (d.driver || "Your driver") + " accepted your ride" + (d.fare ? " - fare $" + Number(d.fare).toFixed(2) : "") + "."]; },
    started: function () { return ["info", "Your ride has started."]; },
    completed: function (d) { return ["success", "Ride completed" + (d.payment_status === "failed" ? " - the payment failed, please retry with another method." : ".")]; },
    cancelled: function () { return ["dark", "The ride was cancelled."]; },
    driver_left: function (d) { return ["warning", (d.driver || "The driver") + " left the ride; it is open again - select another driver."]; },
    no_drivers: function () { return ["danger", "No driver is available for this ride."]; }
  };

  if (!window.EventSource) { return; }
  var source = new EventSource(page.dataset.eventsUrl, { withCredentials: true });
  var status = document.getElementById("ride-live-status");
  source.addEventListener("hello", function (ev) {
    if (status) { status.textContent = "live"; status.className = "badge bg-success"; }
    var hello = JSON.parse(ev.data);
    if (hello.status !== page.dataset.status) { location.reload(); }  // changed while disconnected
  });
  Object.keys(MESSAGES).forEach(function (name) {
    source.addEventListener(name, function (ev) {
      var data = JSON.parse(ev.data);
      var msg = MESSAGES[name](data);
      banner(msg[1], msg[0]);
      sessionStorage.setItem(NOTICE_KEY, msg[0] + "\t" + msg[1]);
      source.close();
      setTimeout(function () { location.reload(); }, 1200);  // re-render the page in its new state
    });
  });
  source.onerror = function () { if (status) { status.textContent = "reconnecting…"; status.className = "badge bg-warning text-dark"; } };
})();
