"""
The fixed permission vocabulary. Roles are named bundles of these codes plus a
rank; the rank decides who may manage whom (you can only touch members and
roles ranked strictly below you, and only grant permissions you hold).
"""

PERMISSIONS = {
    "checks.create": "Create check codes for players",
    "checks.view_all": "See checks created by every admin",
    "checks.decide": "Record the final decision on own checks",
    "checks.decide_any": "Record or override the decision on any visible check",
    "checks.export": "Download raw evidence JSON",
    "checks.delete": "Delete checks",
    "team.view": "See the team list",
    "team.manage": "Invite, edit, disable and reset lower-ranked members",
    "roles.manage": "Create and edit lower-ranked roles",
    "audit.view": "Read the audit log",
    "settings.manage": "Change panel settings and trusted checker builds",
}

PERMISSION_GROUPS = [
    ("Checks", ["checks.create", "checks.view_all", "checks.decide", "checks.decide_any",
                "checks.export", "checks.delete"]),
    ("Team", ["team.view", "team.manage", "roles.manage"]),
    ("Panel", ["audit.view", "settings.manage"]),
]

OWNER_SLUG = "owner"
OWNER_RANK = 100

# slug, name, rank, color, permissions, description
DEFAULT_ROLES = [
    (OWNER_SLUG, "Owner", OWNER_RANK, "#ff5a5a", sorted(PERMISSIONS),
     "Full control. Cannot be edited; the last active owner cannot be removed."),
    ("head-admin", "Head Admin", 80, "#f6b949",
     ["checks.create", "checks.view_all", "checks.decide", "checks.decide_any", "checks.export",
      "checks.delete", "team.view", "team.manage", "audit.view"],
     "Runs the admin team: sees every check, overrides decisions, manages admins."),
    ("admin", "Admin", 50, "#6f78ef",
     ["checks.create", "checks.decide", "checks.export", "team.view"],
     "Checks players and decides on their own checks."),
    ("trainee", "Trainee", 20, "#37d67a",
     ["checks.create"],
     "Can run checks; a senior admin records the decision."),
    ("observer", "Observer", 10, "#b6b6c6",
     ["checks.view_all"],
     "Read-only access to every check (auditors, owners of partner servers)."),
]


def validate_codes(codes):
    unknown = [c for c in codes if c not in PERMISSIONS]
    if unknown:
        raise ValueError(f"unknown permission codes: {unknown}")
    return sorted(set(codes))
