from flask import Blueprint

bp = Blueprint("auth", __name__)

from . import oauth_routes, routes  # noqa: E402,F401  (register routes on the blueprint)
