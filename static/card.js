// Card-on-file tokenisation in the browser.
//
// The card fields have no `name` attribute, so the browser can never post them to our
// server. On submit we send them to the payment vault (data-tokenize-url, authenticated
// with the publishable key), receive a single-use token, wipe the fields and submit the
// form with the token only. Plain static file: the Content-Security-Policy forbids inline JS.
(function () {
  var form = document.getElementById("card-form");
  var input = document.getElementById("number");
  var hint = document.getElementById("brand-hint");
  if (!form || !input) { return; }

  function brand(n) {
    if (/^4/.test(n)) return "Visa";
    if (/^(5[1-5]|2[2-7])/.test(n)) return "Mastercard";
    if (/^3[47]/.test(n)) return "American Express";
    if (/^(6011|65|64[4-9])/.test(n)) return "Discover";
    return "";
  }
  input.addEventListener("input", function () {
    var digits = input.value.replace(/\D/g, "").slice(0, 19);
    var groups = /^3[47]/.test(digits) ? [4, 6, 5] : [4, 4, 4, 4, 3];
    var out = [], i = 0;
    for (var g = 0; g < groups.length && i < digits.length; g++) {
      out.push(digits.substr(i, groups[g]));
      i += groups[g];
    }
    input.value = out.join(" ");
    if (hint) { hint.textContent = brand(digits) ? "Detected: " + brand(digits) : "Visa, Mastercard, American Express, Discover."; }
  });

  var errorBox = document.getElementById("card-error");
  var tokenField = document.getElementById("card_token");
  var submit = document.getElementById("card-submit");
  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.classList.remove("d-none");
    submit.disabled = false;
    submit.textContent = "Save card";
  }

  form.addEventListener("submit", function (ev) {
    if (tokenField.value) { return; }  // already tokenised -> let the form go to our server
    ev.preventDefault();
    errorBox.classList.add("d-none");
    submit.disabled = true;
    submit.textContent = "Securing card…";
    var payload = {
      number: input.value,
      exp_month: document.getElementById("exp_month").value,
      exp_year: document.getElementById("exp_year").value,
      cvc: document.getElementById("cvc").value,
      publishable_key: form.dataset.publishableKey
    };
    fetch(form.dataset.tokenizeUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(payload)
    }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
      .then(function (res) {
        if (!res.ok || !res.body.token) {
          showError(res.body && res.body.message ? res.body.message : "The card could not be tokenised. Please try again.");
          return;
        }
        tokenField.value = res.body.token;
        // Wipe card data from the page before anything is submitted to ServiceUber.
        form.querySelectorAll("[data-sensitive]").forEach(function (el) { el.value = ""; el.required = false; });
        form.submit();
      })
      .catch(function () { showError("The payment vault could not be reached. Please try again."); });
  });
})();
