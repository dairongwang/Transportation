"""WSGI entry point for production servers.

    gunicorn -w 2 -b 0.0.0.0:8000 wsgi:app          (Linux / macOS)
    waitress-serve --listen=0.0.0.0:8000 wsgi:app    (Windows)
"""

from app import create_app

app = create_app()
