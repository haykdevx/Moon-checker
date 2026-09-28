"""
The fixed permission vocabulary. Roles are named bundles of these codes plus a
rank; the rank decides who may manage whom (you can only touch members and
roles ranked strictly below you, and only grant permissions you hold).
"""
from django.utils.translation import gettext_lazy as _, gettext_noop as N_

PERMISSIONS = {
    "checks.create": _("Create check codes for players"),
    "checks.view_all": _("See checks created by every admin"),
    "checks.decide": _("Record the final decision on own checks"),
    "checks.decide_any": _("Record or override the decision on any visible check"),
    "checks.export": _("Download raw evidence JSON"),
    "checks.delete": _("Delete checks"),
    "team.view": _("See the team list"),
    "team.manage": _("Invite, edit, disable and reset lower-ranked members"),
    "roles.manage": _("Create and edit lower-ranked roles"),
    "audit.view": _("Read the audit log"),
    "settings.manage": _("Change panel settings and trusted checker builds"),
}

PERMISSION_GROUPS = [
    (_("Checks"), ["checks.create", "checks.view_all", "checks.decide", "checks.decide_any",
                   "checks.export", "checks.delete"]),
    (_("Team"), ["team.view", "team.manage", "roles.manage"]),
    (_("Panel"), ["audit.view", "settings.manage"]),
]

OWNER_SLUG = "owner"
OWNER_RANK = 100

# slug, name, rank, color, permissions, description
DEFAULT_ROLES = [
    (OWNER_SLUG, N_("Owner"), OWNER_RANK, "#ff5a5a", sorted(PERMISSIONS),
     N_("Full control. Cannot be edited; the last active owner cannot be removed.")),
    ("head-admin", N_("Head Admin"), 80, "#f6b949",
     ["checks.create", "checks.view_all", "checks.decide", "checks.decide_any", "checks.export",
      "checks.delete", "team.view", "team.manage", "audit.view"],
     N_("Runs the admin team: sees every check, overrides decisions, manages admins.")),
    ("admin", N_("Admin"), 50, "#6f78ef",
     ["checks.create", "checks.decide", "checks.export", "team.view"],
     N_("Checks players and decides on their own checks.")),
    ("trainee", N_("Trainee"), 20, "#37d67a",
     ["checks.create"],
     N_("Can run checks; a senior admin records the decision.")),
    ("observer", N_("Observer"), 10, "#b6b6c6",
     ["checks.view_all"],
     N_("Read-only access to every check (auditors, owners of partner servers).")),
]


DEFAULT_TEXT = {slug: (name, description) for slug, name, _rank, _color, _perms, description in DEFAULT_ROLES}


def validate_codes(codes):
    unknown = [c for c in codes if c not in PERMISSIONS]
    if unknown:
        raise ValueError(f"unknown permission codes: {unknown}")
    return sorted(set(codes))
