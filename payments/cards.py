"""
Card helpers shared by the fake vault (vault.py), the gateway (gateway.py) and the routes.

Nothing in here stores or logs a card number. The helpers exist so that
  * the FAKE vault can validate what the browser sends it (Luhn, expiry, CVC, brand);
  * the merchant side can REFUSE anything that looks like a card number where a token
    belongs (`looks_like_pan`) - defence in depth for the card-on-file rule;
  * every failure has one code and one user-facing message (`PaymentError`,
    `FAILURE_MESSAGES`).

Test cards
----------
The numbers below are the public, well-known processor TEST numbers (Stripe's test
range). They are FAKE: they do not belong to any real account and no real money can move
with them. Every other Luhn-valid number behaves like a healthy card.

  number              behaviour            stage     what happens
  4242424242424242    ok                   -         Visa, everything succeeds
  5555555555554444    ok                   -         Mastercard, everything succeeds
  378282246310005     ok                   -         American Express, everything succeeds
  4000000000000002    card_declined        charge    the validation hold is declined -> cannot be added
  4000000000009995    insufficient_funds   charge    the validation hold is declined -> cannot be added
  4000000000000119    processing_error     charge    the validation hold fails       -> cannot be added
  4000000000000341    card_declined        later     validates (hold OK), every real charge / capture is declined
  4000000000009979    insufficient_funds   limit     LOW BALANCE: holds up to LOW_BALANCE_LIMIT succeed
                                                     (the $1 validation), anything larger is refused
  4000000000000069    expired_card         tokenize  rejected by the vault in the browser
  4000000000000127    incorrect_cvc        tokenize  rejected by the vault in the browser

"stage" tells vault.outcome() WHEN the scripted failure applies; the behaviour travels
inside the signed token so the fake gateway is deterministic across restarts.
"""

from __future__ import annotations

import re

from clock import utcnow

# ------------------------------------------------------------------ test cards

# number -> (behaviour, stage)
TEST_CARDS: dict[str, tuple[str, str]] = {
    "4000000000000002": ("card_declined", "charge"),
    "4000000000009995": ("insufficient_funds", "charge"),
    "4000000000000119": ("processing_error", "charge"),
    "4000000000000341": ("card_declined", "later"),
    "4000000000009979": ("insufficient_funds", "limit"),
    "4000000000000069": ("expired_card", "tokenize"),
    "4000000000000127": ("incorrect_cvc", "tokenize"),
}

# A "low balance" card accepts holds / charges up to this amount (the validation hold) and
# refuses anything larger - used to exercise a refused ride pre-authorisation.
LOW_BALANCE_LIMIT = 5.00

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ------------------------------------------------------------------ errors

FAILURE_MESSAGES: dict[str, str] = {
    # scripted / processor outcomes
    "card_declined": "The card was declined.",
    "insufficient_funds": "The card has insufficient funds.",
    "processing_error": "The payment provider had a processing error. Please try again.",
    "expired_card": "The card has expired.",
    "incorrect_cvc": "The security code (CVC) is incorrect.",
    "wallet_declined": "The wallet provider declined the payment.",
    # input validation (vault)
    "invalid_number": "The card number is invalid.",
    "invalid_expiry": "The expiry date is invalid or in the past.",
    "invalid_cvc": "The security code (CVC) is invalid.",
    # tokens
    "invalid_token": "The payment token is invalid. Please enter the card again.",
    "token_expired": "The payment token has expired. Please enter the card again.",
    "token_used": "The payment token was already used. Please enter the card again.",
    "token_customer_mismatch": "This payment method belongs to a different customer.",
    # merchant-side rules
    "duplicate_card": "This card is already on file.",
    "raw_card_data": ("Card numbers must never be sent to ServiceUber. The card has to be tokenised "
                      "by the payment vault in your browser (JavaScript is required)."),
    "invalid_amount": "The amount is invalid.",
    "void_failed": "The authorisation hold could not be released; it will expire on its own.",
    "refund_failed": "The payment provider refused the refund.",
    "not_configured": ("Real payments are not configured (PAYMENTS_MODE=real needs a gateway "
                       "implementation). Use PAYMENTS_MODE=fake for development."),
}


def failure_message(code: str | None) -> str:
    """User-facing text for a failure code (generic text for unknown / missing codes)."""
    if not code:
        return "The payment could not be processed."
    return FAILURE_MESSAGES.get(code, f"The payment could not be processed ({code}).")


class PaymentError(Exception):
    """A payment operation failed. `code` is machine-readable; str(exc) is user-facing."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        self.message = message or failure_message(code)
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


# ------------------------------------------------------------------ card number helpers

_SEPARATORS_RE = re.compile(r"[\s\-]")
# 13..19 digits, optionally grouped with single spaces / dashes (how people type card numbers)
_PAN_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)")


def normalise_number(number: str | None) -> str:
    """Strip spaces and dashes ("4242 4242-4242 4242" -> "4242424242424242")."""
    return _SEPARATORS_RE.sub("", str(number or ""))


def luhn_valid(number: str | None) -> bool:
    """Luhn (mod 10) check on a normalised number of plausible card length (12..19 digits)."""
    digits = normalise_number(number)
    if not digits.isdigit() or not 12 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def detect_brand(number: str | None) -> str:
    """visa | mastercard | amex | discover | card (unknown)."""
    n = normalise_number(number)
    if n.startswith("4"):
        return "visa"
    if re.match(r"^(5[1-5]|2[2-7])", n):
        return "mastercard"
    if re.match(r"^3[47]", n):
        return "amex"
    if re.match(r"^(6011|65|64[4-9])", n):
        return "discover"
    return "card"


def expiry_valid(exp_month, exp_year) -> bool:
    """Month 1..12, four-digit year, not in the past, not absurdly far in the future."""
    try:
        month, year = int(exp_month), int(exp_year)
    except (TypeError, ValueError):
        return False
    if not 1 <= month <= 12:
        return False
    now = utcnow()
    if year < now.year or year > now.year + 25:
        return False
    return (year, month) >= (now.year, now.month)


def looks_like_pan(value) -> bool:
    """
    True if `value` contains something that looks like a real card number (a 13..19 digit run,
    optionally grouped with spaces / dashes, that passes the Luhn check). Used to refuse raw
    card data anywhere the app expects a token, a nickname or a name.
    """
    if value is None:
        return False
    text = str(value)
    if len(text) > 4096:  # nothing legitimate in our forms is this long; do not scan megabytes
        text = text[:4096]
    for match in _PAN_CANDIDATE_RE.finditer(text):
        if luhn_valid(match.group(0)):
            return True
    return False
