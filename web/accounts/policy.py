"""
Who may manage whom. All rules are rank-based so a compromised or rogue
lower-ranked account can never promote itself or touch anyone above it.
"""
from .models import Role, User
from .permissions import OWNER_SLUG


def active_owner_count():
    return User.objects.filter(role__slug=OWNER_SLUG, is_active=True).count()


def assignable_roles(actor):
    """Roles the actor may hand out: strictly below their rank (owners may also add owners)."""
    if not actor.can("team.manage"):
        return Role.objects.none()
    qs = Role.objects.filter(rank__lt=actor.rank)
    if actor.is_owner:
        qs = qs | Role.objects.filter(slug=OWNER_SLUG)
    return qs.order_by("-rank", "name")


def can_manage_member(actor, target):
    if actor.pk == target.pk or not actor.can("team.manage"):
        return False
    if actor.is_owner:
        return True  # owners may act on co-owners; last-owner protection is separate
    return actor.rank > target.rank


def would_orphan_owners(target, new_role=None, deactivate=False):
    """True if the change would leave the panel without any active owner."""
    if not (target.is_owner and target.is_active):
        return False
    losing = deactivate or (new_role is not None and not new_role.is_owner_role)
    return losing and active_owner_count() <= 1


def can_edit_role(actor, role):
    if not actor.can("roles.manage") or role.is_owner_role:
        return False
    return role.rank < actor.rank


def grantable_permissions(actor):
    """A role editor can only grant permissions they hold themselves."""
    from .permissions import PERMISSIONS
    return [c for c in PERMISSIONS if actor.can(c)]
