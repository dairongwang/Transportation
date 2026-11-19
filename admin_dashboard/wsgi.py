"""WSGI entry point (production):
    gunicorn -w 2 -b 0.0.0.0:8001 wsgi:app          (Linux / macOS)
    waitress-serve --listen=0.0.0.0:8001 wsgi:app    (Windows)
"""

from uber_admin import create_app

app = create_app()
