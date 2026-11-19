"""Development server for the admin dashboard:  python app.py  ->  http://127.0.0.1:5001"""

import os

from uber_admin import create_app

if __name__ == "__main__":
    app = create_app()
    host = os.environ.get("ADMIN_HOST", "127.0.0.1")
    port = int(os.environ.get("ADMIN_PORT", 5001))
    app.logger.info("Admin dashboard on http://%s:%s  (ServiceUber Admin API: %s)", host, port, app.config["MAIN_APP_API_URL"])
    app.run(host=host, port=port, debug=app.config.get("DEBUG", False))
