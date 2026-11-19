"""Shared fixtures. Makes the project root importable regardless of OS / cwd / how pytest is invoked."""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Fail early with an actionable message when the interpreter running pytest does not
# have the project's dependencies (the classic "ModuleNotFoundError: No module named
# 'flask_...'" when pytest is started with a different Python than the one used for
# `pip install`, e.g. the global interpreter instead of .venv).
_REQUIRED = {"flask": "Flask", "flask_sqlalchemy": "Flask-SQLAlchemy", "flask_login": "Flask-Login",
             "dotenv": "python-dotenv", "flask_limiter": "Flask-Limiter"}
_missing = [dist for mod, dist in _REQUIRED.items() if importlib.util.find_spec(mod) is None]
if _missing:
    raise pytest.UsageError(
        f"Missing packages: {', '.join(_missing)}.\n"
        f"pytest is running with: {sys.executable}\n"
        f"Install into THAT interpreter:  \"{sys.executable}\" -m pip install -r requirements.txt\n"
        "or use the launchers which install first:  ./run.sh --test | run.bat --test | .\\run.ps1 -Test"
    )

from app import create_app  # noqa: E402
from extensions import db  # noqa: E402


@pytest.fixture
def app(tmp_path):
    """Isolated app: in-memory DB, memory delivery backends, private instance folder."""
    app = create_app("testing")
    app.instance_path = str(tmp_path)  # outbox file etc. never touch the real instance/ folder
    with app.app_context():
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def _isolated_event_broker():
    """Push-event subscribers never leak from one test into the next."""
    from rides.events import broker

    broker.clear()
    yield
    broker.clear()


@pytest.fixture
def fleet(app):
    """The DUMMY demo driver bots (dummy_driver_1..8), online around the demo city, background-checked."""
    from rides import simulator

    simulator.seed_demo_drivers()
    return simulator.bots()


@pytest.fixture
def rider(app):
    """A logged-out rider account with a passed background check."""
    from helpers import make_user

    return make_user("dummy_rider")


@pytest.fixture
def rider_client(app, rider):
    """A test client logged in as the background-checked rider."""
    from helpers import login

    c = app.test_client()
    login(c, "dummy_rider")
    return c
