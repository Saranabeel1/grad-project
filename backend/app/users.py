"""Manage sign-in accounts from the terminal (there is no sign-up page on purpose).

  python -m app.users add                 asks for name, email, role, projects and password
  python -m app.users list
  python -m app.users password EMAIL      set a new password
  python -m app.users projects EMAIL "Project G,Project H"
  python -m app.users remove EMAIL

Run it in the backend folder with the same DATABASE_URL as the portal (start-portal.cmd uses daily.db):
  set DATABASE_URL=sqlite:///./daily.db
"""
import getpass
import sys

from sqlalchemy import select, update

from . import models
from .auth import hash_password
from .database import SessionLocal, upgrade


def ask_password() -> str:
    while True:
        first = getpass.getpass("Password (at least 8 characters, hidden while typing): ")
        if len(first) < 8:
            print("Too short.")
        elif first != getpass.getpass("Same password again: "):
            print("The two passwords are different.")
        else:
            return first


def find(db, email):
    user = db.scalar(select(models.User).where(models.User.email == email.lower().strip()))
    if not user:
        sys.exit(f"No account with the email {email}")
    return user


def main(argv):
    upgrade()
    db = SessionLocal()
    cmd = argv[0] if argv else "help"
    if cmd == "add":
        name = input("Full name: ").strip()
        email = input("Email: ").strip().lower()
        if db.scalar(select(models.User).where(models.User.email == email)):
            sys.exit("That email already has an account.")
        role = ""
        while role not in ("manager", "developer"):
            role = input("Role (manager / developer): ").strip().lower()
        projects = ""
        if role == "developer":
            projects = input('Projects, separated by commas (for example: Project G): ').strip()
        db.add(models.User(name=name, email=email, role=role, projects=projects, password_hash=hash_password(ask_password())))
        db.commit()
        print(f"Account made for {name} ({role}).")
    elif cmd == "list":
        for u in db.scalars(select(models.User).order_by(models.User.role, models.User.name)):
            print(f"{u.email:35} {u.role:10} {u.name:30} {u.projects or 'all projects'}")
    elif cmd == "password" and len(argv) == 2:
        user = find(db, argv[1])
        user.password_hash = hash_password(ask_password())
        db.commit()
        print("Password changed.")
    elif cmd == "projects" and len(argv) == 3:
        user = find(db, argv[1])
        user.projects = argv[2]
        db.commit()
        print(f"{user.name} now sees: {user.projects or 'no projects'}")
    elif cmd == "remove" and len(argv) == 2:
        user = find(db, argv[1])
        db.execute(update(models.Finding).where(models.Finding.assignee_id == user.id).values(assignee_id=None))
        db.execute(update(models.FindingEvent).where(models.FindingEvent.user_id == user.id).values(user_id=None))
        db.delete(user)
        db.commit()
        print("Account removed (their findings are now unassigned).")
    else:
        print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
