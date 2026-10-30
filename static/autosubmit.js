// Auto-submits the form with id="autosubmit" (used by the fake Apple form_post page).
// Kept in a static file because the Content-Security-Policy forbids inline scripts.
(function () {
  var f = document.getElementById("autosubmit");
  if (f) { setTimeout(function () { f.submit(); }, 300); }
})();
