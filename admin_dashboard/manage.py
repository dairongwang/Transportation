#!/usr/bin/env python3
"""
Operate the dashboard's own operator accounts (no ServiceUber access needed).

    python manage.py list-users
    python manage.py create-user <username> --role manager|viewer [--name "Full Name"]
    python manage.py set-password <username>
    python manage.py set-role <username> manager|viewer
    python manage.py disable-user <username> | enable-user <username>

Passwords are asked interactively (never put real passwords on the command line);
--password exists only for scripted DUMMY test setups.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from uber_admin import create_app
from uber_admin.extensions import db
from uber_admin.models import ROLES, AdminUser


def _password(args, app) -> str:
    pw = args.password or getpass.getpass("New password: ")
    if not args.password and pw != getpass.getpass("Repeat: "):
        sys.exit("Passwords do not match.")
    if len(pw) < app.config["PASSWORD_MIN_LENGTH"]:
        sys.exit(f"Password must be at least {app.config['PASSWORD_MIN_LENGTH']} characters.")
    return pw


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list-users")
    c = sub.add_parser("create-user"); c.add_argument("username"); c.add_argument("--role", choices=ROLES, default="viewer")
    c.add_argument("--name"); c.add_argument("--password")
    s = sub.add_parser("set-password"); s.add_argument("username"); s.add_argument("--password")
    r = sub.add_parser("set-role"); r.add_argument("username"); r.add_argument("role", choices=ROLES)
    for name in ("disable-user", "enable-user"):
        sub.add_parser(name).add_argument("username")
    args = p.parse_args(argv)

    app = create_app(overrides={"SEED_DEMO_USERS": False})
    with app.app_context():
        if args.cmd == "list-users":
            for u in AdminUser.query.order_by(AdminUser.username).all():
                print(f"{u.username:24} {u.role:8} {'active' if u.is_active else 'DISABLED':9} last login {u.last_login_at or '—'}")
            return 0
        user = AdminUser.query.filter_by(username=args.username).first()
        if args.cmd == "create-user":
            if user is not None:
                sys.exit(f"User {args.username} already exists.")
            user = AdminUser(username=args.username, role=args.role, display_name=args.name)
            user.set_password(_password(args, app))
            db.session.add(user)
        elif user is None:
            sys.exit(f"No user {args.username}.")
        elif args.cmd == "set-password":
            user.set_password(_password(args, app))  # also signs out the user's sessions
            user.locked_until, user.failed_logins = None, 0
        elif args.cmd == "set-role":
            user.role = args.role
        else:
            user.is_active = args.cmd == "enable-user"
        db.session.commit()
        print(f"{args.cmd}: {user.username} ({user.role}, {'active' if user.is_active else 'disabled'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
