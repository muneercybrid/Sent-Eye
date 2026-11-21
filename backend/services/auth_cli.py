"""Interactive commands for Sent Eye account provisioning."""
from __future__ import annotations

import getpass
import re
import sys

from backend.core.runner import MODULE_REGISTRY
from backend.services.auth_store import AuthStore
from backend.services.security import hash_password


ADMIN_EMAIL = "admin@senteye.live"
OPERATOR_EMAIL = "muneerstuxnet@gmail.com"
EMAIL_PATTERN = re.compile(r"^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")


def read_name(label: str) -> str | None:
    name = " ".join(input(f"{label} display name: ").split())
    if len(name) < 2 or len(name) > 100:
        print("Name must be between 2 and 100 characters.")
        return None
    return name


def read_password(label: str) -> str | None:
    password = getpass.getpass(f"Create {label} password (12+ characters): ")
    confirmation = getpass.getpass("Confirm password: ")

    if len(password) < 12 or len(password) > 256:
        print("Password must be between 12 and 256 characters.")
        return None
    if password != confirmation:
        print("Passwords do not match.")
        return None
    return password


def create_admin() -> int:
    store = AuthStore()
    store.init_db()

    if store.count_admins():
        print("An administrator already exists. Initial setup is locked.")
        return 1

    if store.get_user_by_email(ADMIN_EMAIL):
        print(f"{ADMIN_EMAIL} is already registered with another account.")
        return 1

    print(f"Creating the Sent Eye platform administrator: {ADMIN_EMAIL}")
    full_name = read_name("Administrator")
    if not full_name:
        return 1

    password = read_password("administrator")
    if password is None:
        return 1

    try:
        admin = store.create_first_admin(
            email=ADMIN_EMAIL,
            full_name=full_name,
            password_hash=hash_password(password),
        )
    except Exception as exc:
        print(f"Administrator creation failed: {type(exc).__name__}: {exc}")
        return 1

    print()
    print("Initial administrator created successfully.")
    print(f"Account: {admin['email']}")
    print("Role: admin")
    print("Access: all registered modules and administrator features.")
    print("Next: provision the unrestricted operator account.")
    return 0


def create_operator() -> int:
    store = AuthStore()
    store.init_db()

    admin = store.get_user_by_email(ADMIN_EMAIL)
    if not admin or admin["role"] != "admin" or admin["status"] != "approved":
        print("Create the approved platform administrator first.")
        return 1

    if store.get_user_by_email(OPERATOR_EMAIL):
        print(f"{OPERATOR_EMAIL} already exists. No changes were made.")
        return 1

    print(f"Creating unrestricted operator: {OPERATOR_EMAIL}")
    full_name = read_name("Operator")
    if not full_name:
        return 1

    password = read_password("operator")
    if password is None:
        return 1

    modules = sorted({module.name for module in MODULE_REGISTRY})
    try:
        operator = store.create_unrestricted_operator(
            email=OPERATOR_EMAIL,
            full_name=full_name,
            password_hash=hash_password(password),
            module_names=modules,
            admin_user_id=admin["user_id"],
        )
    except Exception as exc:
        print(f"Operator creation failed: {type(exc).__name__}: {exc}")
        return 1

    print()
    print("Unrestricted operator created successfully.")
    print(f"Account: {operator['email']}")
    print("Role: user")
    print(f"Enabled modules: {len(modules)}")
    for name in modules:
        print(f"  - {name}")
    print("Daily quota: unlimited")
    print("Monthly quota: unlimited")
    print("Administrator features: not granted")
    return 0


def main() -> int:
    commands = {
        "create-admin": create_admin,
        "create-operator": create_operator,
    }
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        print("Usage:")
        print("  python -m backend.services.auth_cli create-admin")
        print("  python -m backend.services.auth_cli create-operator")
        return 2
    return commands[sys.argv[1]]()


if __name__ == "__main__":
    raise SystemExit(main())
