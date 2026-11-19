// Browser GPS for drivers (dashboard / Drive page) and riders (request form).
//
// Driver card (#driver-card):
//   * "Use my GPS location"  -> navigator.geolocation -> POST data-location-url (JSON, X-CSRF-Token)
//   * "keep my location updated" -> watchPosition; posts when moved > 25 m or every 60 s
//   * "Available to drive"    -> if the browser has a GPS fix, it is submitted together with
//                                the switch so one click sets the position AND availability
// Rider form (#pickup with #pickup-gps): fills the pickup field with "lat,lng".
//
// Geolocation only works in a secure context (https:// or localhost); we say so instead
// of failing silently. Plain static file: the Content-Security-Policy forbids inline JS.
(function () {
  var secure = window.isSecureContext || location.hostname === "localhost" || location.hostname === "127.0.0.1";
  var geo = navigator.geolocation;

  // ------------------------------------------------------------------ driver card
  var card = document.getElementById("driver-card");
  if (card) {
    var status = document.getElementById("gps-status");
    var gpsButton = document.getElementById("gps-button");
    var follow = document.getElementById("gps-follow");
    var latField = document.getElementById("avail-lat");
    var lngField = document.getElementById("avail-lng");
    var goAvailable = document.getElementById("go-available");
    var lastFix = null, lastSent = 0, watchId = null, reloading = false;

    function say(msg, cls) {
      if (!status) { return; }
      status.textContent = msg;
      status.className = "small " + (cls || "text-muted");
    }
    if (!geo || !secure) {
      if (gpsButton) { gpsButton.disabled = true; }
      if (follow) { follow.disabled = true; }
      var note = document.getElementById("gps-insecure");
      if (note) { note.classList.remove("d-none"); }
      say(geo ? "GPS unavailable on http://" : "this browser has no geolocation");
      return;
    }

    function distanceM(a, b) {
      var r = 6371008.8, toRad = Math.PI / 180;
      var dLat = (b.latitude - a.latitude) * toRad, dLng = (b.longitude - a.longitude) * toRad;
      var h = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
              Math.cos(a.latitude * toRad) * Math.cos(b.latitude * toRad) * Math.sin(dLng / 2) * Math.sin(dLng / 2);
      return 2 * r * Math.asin(Math.sqrt(h));
    }

    function post(coords, online, reloadAfter) {
      var body = { lat: coords.latitude, lng: coords.longitude };
      if (online !== undefined) { body.online = online; }
      return fetch(card.dataset.locationUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json", "X-CSRF-Token": card.dataset.csrf },
        body: JSON.stringify(body),
        credentials: "same-origin"
      }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
        .then(function (res) {
          if (!res.ok) { say(res.body.error || "could not save the position", "text-danger"); return; }
          lastSent = Date.now();
          say("position saved " + coords.latitude.toFixed(5) + ", " + coords.longitude.toFixed(5) +
              (res.body.visible_to_riders ? " - visible to riders" : " - " + res.body.reason), res.body.visible_to_riders ? "text-success" : "text-muted");
          if (reloadAfter && !reloading) { reloading = true; location.reload(); }
        })
        .catch(function () { say("network error while saving the position", "text-danger"); });
    }

    function onFix(pos) {
      lastFix = pos.coords;
      if (latField) { latField.value = pos.coords.latitude; }
      if (lngField) { lngField.value = pos.coords.longitude; }
    }
    function onError(err) {
      var msg = { 1: "location permission denied", 2: "position unavailable", 3: "GPS timed out" }[err.code] || err.message;
      say(msg, "text-danger");
      if (gpsButton) { gpsButton.disabled = false; }
    }
    var options = { enableHighAccuracy: true, timeout: 15000, maximumAge: 10000 };

    if (gpsButton) {
      gpsButton.addEventListener("click", function () {
        gpsButton.disabled = true;
        say("locating…");
        geo.getCurrentPosition(function (pos) {
          onFix(pos);
          gpsButton.disabled = false;
          post(pos.coords, undefined, true);  // reload so the card shows the new position / visibility
        }, onError, options);
      });
    }

    if (follow) {
      follow.addEventListener("change", function () {
        if (follow.checked) {
          say("following your position…");
          watchId = geo.watchPosition(function (pos) {
            var moved = lastFix ? distanceM(lastFix, pos.coords) : Infinity;
            onFix(pos);
            if (moved > 25 || Date.now() - lastSent > 60000) { post(pos.coords); }
          }, onError, options);
        } else if (watchId !== null) {
          geo.clearWatch(watchId);
          watchId = null;
          say("stopped following");
        }
      });
    }

    // "Available to drive": grab a fix first when we have none, so the switch does not fail
    // with "post a position before going online".
    if (goAvailable && card.dataset.hasLocation !== "1") {
      goAvailable.addEventListener("click", function (ev) {
        if (latField.value) { return; }  // already have a fix in the hidden fields -> submit normally
        ev.preventDefault();
        goAvailable.disabled = true;
        say("locating…");
        geo.getCurrentPosition(function (pos) {
          onFix(pos);
          goAvailable.form.submit();
        }, function (err) {
          onError(err);
          goAvailable.disabled = false;
          say("no GPS fix - pick a landmark below, then try again", "text-danger");
        }, options);
      });
    }
  }

  // ------------------------------------------------------------------ rider pickup
  var pickupButton = document.getElementById("pickup-gps");
  var pickup = document.getElementById("pickup");
  if (pickupButton && pickup) {
    if (!geo || !secure) {
      pickupButton.disabled = true;
      pickupButton.title = "GPS needs https:// or localhost";
      return;
    }
    pickupButton.addEventListener("click", function () {
      pickupButton.disabled = true;
      pickupButton.textContent = "📍 locating…";
      geo.getCurrentPosition(function (pos) {
        pickup.value = pos.coords.latitude.toFixed(5) + "," + pos.coords.longitude.toFixed(5);
        pickupButton.disabled = false;
        pickupButton.textContent = "📍 Use my GPS location";
      }, function () {
        pickupButton.disabled = false;
        pickupButton.textContent = "📍 GPS unavailable - type a place";
      }, { enableHighAccuracy: true, timeout: 15000, maximumAge: 10000 });
    });
  }
})();
