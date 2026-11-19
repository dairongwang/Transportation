"""
Ride hailing: a rider requests a ride, the app searches online drivers near the pickup
point and ranks them by distance, rating, price and acceptance rate, then dispatches.

  geo.py        geocoder + router interface and the offline STUB implementation
  matching.py   candidate search, scoring / ranking and the dispatch state machine
  simulator.py  demo "driver bots" (dev tools) so the flow can be exercised solo
  routes.py     HTML pages + small JSON API  (blueprint mounted at /rides and /drive)
  chat.py       rider <-> driver chat room, opened when the order is placed (live via SSE)
  chat_routes.py  chat page form + JSON API
"""

from flask import Blueprint

bp = Blueprint("rides", __name__)

from . import chat_routes, routes  # noqa: E402,F401  (registers the routes on the blueprint)
