"""
Who may manage whom. Two boundaries apply together, in every view that changes a
membership (invites, accepting an invite, member edits, member actions, role edits):

- rank: an actor acts only below their own rank (owners also on co-owners);
- permissions: an actor can hand out, edit or take over only what they hold themselves.
  A custom role may rank lower but carry permissions the actor lacks; such a role cannot
  be assigned by them, and its members cannot be managed by them (a password-reset link
  for such a member would be a way into those permissions).

Last-owner protection is checked again under a lock when a change is saved (views).
"""
from .models import Role, User
from .permissions import OWNER_SLUG, PERMISSIONS


def active_owner_count():
    return User.objects.filter(role__slug=OWNER_SLUG, is_active=True).count()


def held_permissions(actor):
    return {c for c in PERMISSIONS if actor.can(c)}


def holds_all(actor, role):
    """True if the actor holds every permission the role grants (owners hold all)."""
    if actor.is_owner:
        return actor.is_active
    if role.is_owner_role:
        return False
    return set(role.permissions) <= held_permissions(actor)


def assignable_roles(actor):
    """Roles the actor may hand out: strictly below their rank (owners may also add owners), and only
    roles whose permissions the actor holds."""
    if not actor.can("team.manage"):
        return Role.objects.none()
    qs = Role.objects.filter(rank__lt=actor.rank)
    if actor.is_owner:
        qs = qs | Role.objects.filter(slug=OWNER_SLUG)
    allowed = [r.pk for r in qs if holds_all(actor, r)]
    return Role.objects.filter(pk__in=allowed).order_by("-rank", "name")


def can_manage_member(actor, target):
    if actor.pk == target.pk or not actor.can("team.manage"):
        return False
    if actor.is_owner:
        return True  # owners may act on co-owners; last-owner protection is separate
    return actor.rank > target.rank and holds_all(actor, target.role)


def would_orphan_owners(target, new_role=None, deactivate=False):
    """True if the change would leave the panel without any active owner."""
    if not (target.is_owner and target.is_active):
        return False
    losing = deactivate or (new_role is not None and not new_role.is_owner_role)
    return losing and active_owner_count() <= 1


def can_edit_role(actor, role):
    if not actor.can("roles.manage") or role.is_owner_role:
        return False
    return role.rank < actor.rank and holds_all(actor, role)


def grantable_permissions(actor):
    """A role editor can only grant permissions they hold themselves."""
    return [c for c in PERMISSIONS if actor.can(c)]
