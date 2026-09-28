import time
from functools import wraps

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Count
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.text import slugify
from django.utils.translation import gettext as _t
from django.views.decorators.http import require_POST

from core import ratelimit
from core.audit import client_ip, record
from core.models import AuditEvent, SiteSettings

from . import policy, totp
from .forms import (ChangePasswordForm, ConfirmTotpForm, DisableTotpForm, InviteAcceptForm, InviteForm,
                    LoginForm, MemberForm, ProfileForm, RoleForm, SetPasswordForm, TwoFactorForm)
from .models import Invite, Role, User

PENDING_2FA_SECONDS = 300
LOCK_WINDOW = 15 * 60


def perm_required(code):
    def deco(view):
        @wraps(view)
        @login_required
        def wrapped(request, *args, **kwargs):
            if not request.user.can(code):
                raise PermissionDenied
            return view(request, *args, **kwargs)
        return wrapped
    return deco


def _safe_next(request, fallback="checks:dashboard"):
    nxt = request.POST.get("next") or request.GET.get("next")
    if nxt and url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()},
                                               require_https=request.is_secure()):
        return nxt
    return reverse(fallback)


def _finish_login(request, user, next_url=None):
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    ratelimit.reset("login-pair", f"{client_ip(request)}:{user.username}")
    record(request, "login.ok", user.username, actor=user)
    return redirect(next_url or _safe_next(request))


# --- sign in / out --------------------------------------------------------

def login_view(request):
    if request.user.is_authenticated:
        return redirect("checks:dashboard")
    form = LoginForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        ip = client_ip(request)
        alias = form.cleaned_data["username"].strip().lower()
        if (ratelimit.exceeded("login-ip", ip, 30) or ratelimit.exceeded("login-user", alias, 10)
                or ratelimit.exceeded("login-pair", f"{ip}:{alias}", 5)):
            record(request, "login.throttled", alias)
            form.add_error(None, _t("Too many failed attempts. Wait 15 minutes and try again."))
        else:
            user = authenticate(request, username=alias, password=form.cleaned_data["password"])
            if user is None:
                ratelimit.hit("login-ip", ip, 3600)
                ratelimit.hit("login-user", alias, LOCK_WINDOW)
                ratelimit.hit("login-pair", f"{ip}:{alias}", LOCK_WINDOW)
                record(request, "login.failed", alias)
                form.add_error(None, _t("Wrong alias or password."))
            elif user.totp_enabled:
                request.session.cycle_key()
                request.session["pending_2fa"] = {"uid": user.pk, "at": time.time(), "tries": 0,
                                                  "next": _safe_next(request)}
                return redirect("accounts:login_2fa")
            else:
                return _finish_login(request, user)
    return render(request, "accounts/login.html", {"form": form, "next": request.GET.get("next", "")})


def login_2fa(request):
    pending = request.session.get("pending_2fa")
    if not pending or time.time() - pending["at"] > PENDING_2FA_SECONDS:
        request.session.pop("pending_2fa", None)
        return redirect("accounts:login")
    user = User.objects.filter(pk=pending["uid"], is_active=True).select_related("role").first()
    if user is None:
        request.session.pop("pending_2fa", None)
        return redirect("accounts:login")
    form = TwoFactorForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        if ratelimit.exceeded("2fa-user", user.pk, 10):
            request.session.pop("pending_2fa", None)
            record(request, "login.2fa_throttled", user.username, actor=user)
            messages.error(request, _t("Too many wrong codes. Wait 15 minutes."))
            return redirect("accounts:login")
        code = form.cleaned_data["code"]
        used_recovery = False
        ok = totp.verify_user(user, code)
        if not ok and totp.use_recovery_code(user, code):
            ok = used_recovery = True
        if ok:
            request.session.pop("pending_2fa", None)
            if used_recovery:
                left = user.recovery_codes.filter(used_at__isnull=True).count()
                messages.warning(request, _t("Signed in with a recovery code. %(left)s left — regenerate them soon.") % {"left": left})
                record(request, "login.recovery_code", user.username, actor=user, remaining=left)
            return _finish_login(request, user, pending.get("next"))
        ratelimit.hit("2fa-user", user.pk, LOCK_WINDOW)
        pending["tries"] += 1
        record(request, "login.2fa_failed", user.username, actor=user)
        if pending["tries"] >= 5:
            request.session.pop("pending_2fa", None)
            messages.error(request, _t("Too many wrong codes. Sign in again."))
            return redirect("accounts:login")
        request.session["pending_2fa"] = pending
        form.add_error("code", _t("That code is not valid."))
    return render(request, "accounts/login_2fa.html", {"form": form, "alias": user.username})


@require_POST
def logout_view(request):
    if request.user.is_authenticated:
        record(request, "logout", request.user.username)
    logout(request)
    return redirect("accounts:login")


def invite_accept(request, token):
    invite = Invite.find_valid(token)
    if invite is not None and invite.kind == Invite.KIND_INVITE:
        creator = invite.created_by
        # the inviter must still be allowed to hand out this role
        if creator is None or not creator.is_active or not policy.assignable_roles(creator).filter(
                pk=invite.role_id).exists():
            invite = None
    if invite is None:
        return render(request, "accounts/invite_invalid.html", status=404)

    if invite.kind == Invite.KIND_RESET:
        form = SetPasswordForm(request.POST or None, user=invite.user)
        if request.method == "POST" and form.is_valid():
            with transaction.atomic():
                user = User.objects.select_for_update().get(pk=invite.user_id)
                user.set_password(form.cleaned_data["new_password"])
                user.must_change_password = False
                user.session_epoch += 1
                user.save()
                invite.used_at, invite.used_by = timezone.now(), user
                invite.save(update_fields=["used_at", "used_by"])
            record(request, "password.reset_used", user.username, actor=user)
            messages.success(request, _t("Password set. Sign in with your new password."))
            return redirect("accounts:login")
        return render(request, "accounts/invite_accept.html", {"form": form, "invite": invite})

    form = InviteAcceptForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            locked = Invite.objects.select_for_update().get(pk=invite.pk)
            if locked.used_at is not None:
                return render(request, "accounts/invite_invalid.html", status=404)
            user = User.objects.create_user(
                form.cleaned_data["username"], form.cleaned_data["new_password"], role=invite.role,
                display_name=form.cleaned_data["display_name"], created_by=invite.created_by)
            locked.used_at, locked.used_by = timezone.now(), user
            locked.save(update_fields=["used_at", "used_by"])
        record(request, "member.joined", user.username, actor=user, role=invite.role.slug,
               invited_by=invite.created_by.username if invite.created_by else None)
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        messages.success(request, _t("Welcome to the team, %(name)s.") % {"name": user.label})
        return redirect("checks:dashboard")
    return render(request, "accounts/invite_accept.html", {"form": form, "invite": invite})


# --- own account ------------------------------------------------------------

@login_required
def account(request):
    user = request.user
    form = ProfileForm(request.POST or None, instance=user)
    if request.method == "POST" and form.is_valid():
        form.save()
        record(request, "account.profile_updated", user.username, fields=form.changed_data)
        messages.success(request, _t("Profile saved."))
        return redirect("accounts:account")
    return render(request, "accounts/account.html", {
        "form": form,
        "recovery_left": user.recovery_codes.filter(used_at__isnull=True).count(),
        "require_2fa": SiteSettings.load().require_2fa,
        "disable_form": DisableTotpForm(),
    })


@login_required
def password_change(request):
    form = ChangePasswordForm(request.POST or None, user=request.user)
    if request.method == "POST" and form.is_valid():
        user = request.user
        user.set_password(form.cleaned_data["new_password"])
        user.must_change_password = False
        user.save()
        update_session_auth_hash(request, user)
        record(request, "password.changed", user.username)
        messages.success(request, _t("Password changed."))
        return redirect("accounts:account")
    return render(request, "accounts/password.html", {"form": form, "forced": request.user.must_change_password})


@login_required
def twofa_setup(request):
    user = request.user
    if user.totp_enabled:
        return redirect("accounts:account")
    secret = request.session.get("totp_pending_secret")
    if not secret:
        secret = totp.new_secret()
        request.session["totp_pending_secret"] = secret
    form = ConfirmTotpForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        step = totp.match_step(secret, form.cleaned_data["code"])
        if step is None:
            form.add_error("code", _t("That code does not match. Check the phone's clock and try again."))
        else:
            user.totp_secret, user.totp_enabled, user.totp_last_step = secret, True, step
            user.save(update_fields=["totp_secret", "totp_enabled", "totp_last_step"])
            request.session.pop("totp_pending_secret", None)
            request.session["show_recovery"] = totp.issue_recovery_codes(user)
            record(request, "2fa.enabled", user.username)
            return redirect("accounts:twofa_recovery")
    uri = totp.provisioning_uri(user, secret)
    return render(request, "accounts/twofa_setup.html", {
        "form": form, "secret": secret, "qr": totp.qr_svg(uri),
        "forced": SiteSettings.load().require_2fa,
    })


@login_required
def twofa_recovery(request):
    codes = request.session.pop("show_recovery", None)
    if not codes:
        return redirect("accounts:account")
    return render(request, "accounts/twofa_recovery.html", {"codes": codes})


@login_required
@require_POST
def twofa_regenerate(request):
    user = request.user
    if not user.totp_enabled or not totp.verify_user(user, request.POST.get("code", "")):
        messages.error(request, _t("Enter a valid authenticator code to regenerate recovery codes."))
        return redirect("accounts:account")
    request.session["show_recovery"] = totp.issue_recovery_codes(user)
    record(request, "2fa.recovery_regenerated", user.username)
    return redirect("accounts:twofa_recovery")


@login_required
@require_POST
def twofa_disable(request):
    user = request.user
    if SiteSettings.load().require_2fa:
        messages.error(request, _t("Two-factor authentication is mandatory on this panel."))
        return redirect("accounts:account")
    form = DisableTotpForm(request.POST)
    if form.is_valid() and user.check_password(form.cleaned_data["password"]) \
            and totp.verify_user(user, form.cleaned_data["code"]):
        user.totp_enabled, user.totp_secret = False, ""
        user.save(update_fields=["totp_enabled", "totp_secret"])
        user.recovery_codes.all().delete()
        record(request, "2fa.disabled", user.username)
        messages.success(request, _t("Two-factor authentication disabled."))
    else:
        messages.error(request, _t("Password or code is wrong."))
    return redirect("accounts:account")


@login_required
@require_POST
def signout_everywhere(request):
    request.user.bump_sessions()
    update_session_auth_hash(request, request.user)
    record(request, "account.signout_everywhere", request.user.username)
    messages.success(request, _t("All other sessions were signed out."))
    return redirect("accounts:account")


# --- team -------------------------------------------------------------------

def _flash_link(request, label, token):
    request.session["flash_link"] = {"label": label, "url": request.build_absolute_uri(
        reverse("accounts:invite_accept", args=[token]))}


@perm_required("team.view")
def team(request):
    actor = request.user
    members = (User.objects.select_related("role")
               .annotate(check_count=Count("check_sessions"))
               .order_by("-role__rank", "username"))
    rows = [(m, policy.can_manage_member(actor, m)) for m in members]
    roles = policy.assignable_roles(actor)
    invites = []
    if actor.can("team.manage"):
        invites = Invite.objects.filter(used_at__isnull=True, expires_at__gt=timezone.now()) \
            .select_related("role", "user", "created_by")
    return render(request, "team/team.html", {
        "rows": rows, "invites": invites, "invite_form": InviteForm(roles=roles),
        "flash_link": request.session.pop("flash_link", None),
    })


@perm_required("team.manage")
@require_POST
def invite_create(request):
    form = InviteForm(request.POST, roles=policy.assignable_roles(request.user))
    if not form.is_valid():
        messages.error(request, _t("Pick a role you are allowed to assign."))
        return redirect("accounts:team")
    invite, token = Invite.issue(Invite.KIND_INVITE, request.user, hours=form.cleaned_data["hours"],
                                 role=form.cleaned_data["role"], note=form.cleaned_data["note"])
    record(request, "invite.created", invite.note or f"invite #{invite.pk}", role=invite.role.slug,
           hours=form.cleaned_data["hours"])
    _flash_link(request, _t("Invite link for a new %(role)s") % {"role": invite.role.label}, token)
    return redirect("accounts:team")


@perm_required("team.manage")
@require_POST
def invite_revoke(request, pk):
    invite = get_object_or_404(Invite, pk=pk, used_at__isnull=True)
    allowed = (invite.kind == Invite.KIND_INVITE and policy.assignable_roles(request.user).filter(
        pk=invite.role_id).exists()) or (invite.kind == Invite.KIND_RESET and invite.user is not None
                                         and policy.can_manage_member(request.user, invite.user))
    if not allowed:
        raise PermissionDenied
    invite.expires_at = timezone.now()
    invite.save(update_fields=["expires_at"])
    record(request, "invite.revoked", f"invite #{invite.pk}")
    messages.success(request, _t("Link revoked."))
    return redirect("accounts:team")


def _member_or_404(request, alias):
    member = User.objects.select_related("role").filter(username=alias.lower()).first()
    if member is None:
        raise Http404
    return member


@perm_required("team.view")
def member_detail(request, alias):
    actor, member = request.user, _member_or_404(request, alias)
    manageable = policy.can_manage_member(actor, member)
    roles = policy.assignable_roles(actor)
    form = None
    if manageable:
        form = MemberForm(request.POST or None, roles=roles, initial={
            "role": member.role if roles.filter(pk=member.role_id).exists() else None,
            "display_name": member.display_name, "is_active": member.is_active})
        if request.method == "POST" and form.is_valid():
            new_role, active = form.cleaned_data["role"], form.cleaned_data["is_active"]
            if policy.would_orphan_owners(member, new_role=new_role, deactivate=not active):
                messages.error(request, _t("That would leave the panel without an active owner."))
                return redirect("accounts:member", alias=member.username)
            changes = {}
            if new_role != member.role:
                changes["role"] = [member.role.slug, new_role.slug]
            if active != member.is_active:
                changes["active"] = [member.is_active, active]
            if form.cleaned_data["display_name"] != member.display_name:
                changes["display_name"] = [member.display_name, form.cleaned_data["display_name"]]
            member.role, member.is_active = new_role, active
            member.display_name = form.cleaned_data["display_name"]
            if "role" in changes or "active" in changes:
                member.session_epoch += 1  # force re-login with the new rights
            member.save()
            if changes:
                record(request, "member.updated", member.username, **changes)
            messages.success(request, _t("Member updated."))
            return redirect("accounts:member", alias=member.username)
    events = AuditEvent.objects.filter(target=member.username)[:25] if actor.can("audit.view") else []
    return render(request, "team/member.html", {
        "member": member, "form": form, "manageable": manageable, "events": events,
        "check_count": member.check_sessions.count(),
        "flash_link": request.session.pop("flash_link", None),
    })


@perm_required("team.manage")
@require_POST
def member_action(request, alias, action):
    actor, member = request.user, _member_or_404(request, alias)
    if not policy.can_manage_member(actor, member):
        raise PermissionDenied
    if action == "reset-password":
        invite, token = Invite.issue(Invite.KIND_RESET, actor, hours=24, user=member)
        record(request, "password.reset_issued", member.username)
        _flash_link(request, _t("Password reset link for %(name)s (valid 24 h)") % {"name": member.username}, token)
    elif action == "reset-2fa":
        member.totp_enabled, member.totp_secret = False, ""
        member.session_epoch += 1
        member.save(update_fields=["totp_enabled", "totp_secret", "session_epoch"])
        member.recovery_codes.all().delete()
        record(request, "2fa.reset_by_manager", member.username)
        messages.success(request, _t("2FA reset for %(name)s. They must set it up again at the next sign-in.") % {"name": member.username})
    elif action == "signout":
        member.bump_sessions()
        record(request, "member.signed_out", member.username)
        messages.success(request, _t("%(name)s was signed out everywhere.") % {"name": member.username})
    else:
        raise Http404
    return redirect("accounts:member", alias=member.username)


# --- roles ------------------------------------------------------------------

@perm_required("team.view")
def roles(request):
    actor = request.user
    items = Role.objects.annotate(member_count=Count("members")).order_by("-rank", "name")
    from .permissions import PERMISSIONS
    return render(request, "team/roles.html", {
        "roles": [(r, policy.can_edit_role(actor, r)) for r in items],
        "permissions": PERMISSIONS,
        "can_create": actor.can("roles.manage"),
    })


@perm_required("roles.manage")
def role_edit(request, slug=None):
    actor = request.user
    role = get_object_or_404(Role, slug=slug) if slug else None
    if role is not None and not policy.can_edit_role(actor, role):
        raise PermissionDenied
    form = RoleForm(request.POST or None, instance=role, actor=actor,
                    grantable=policy.grantable_permissions(actor))
    if request.method == "POST" and form.is_valid():
        obj = form.save(commit=False)
        if role is None:
            base = slugify(obj.name)[:30] or "role"
            slug_candidate, n = base, 2
            while Role.objects.filter(slug=slug_candidate).exists():
                slug_candidate, n = f"{base}-{n}", n + 1
            obj.slug = slug_candidate
        obj.save()
        record(request, "role.saved", obj.slug, rank=obj.rank, permissions=obj.permissions)
        if role is not None:
            # everyone holding this role gets fresh sessions with the new rights
            for m in obj.members.all():
                m.bump_sessions()
        messages.success(request, _t("Role %(name)s saved.") % {"name": obj.name})
        return redirect("accounts:roles")
    return render(request, "team/role_edit.html", {"form": form, "role": role})


@perm_required("roles.manage")
@require_POST
def role_delete(request, slug):
    role = get_object_or_404(Role, slug=slug)
    if not policy.can_edit_role(request.user, role) or role.is_system:
        raise PermissionDenied
    if role.members.exists():
        messages.error(request, _t("Move the members to another role first."))
    else:
        record(request, "role.deleted", role.slug)
        role.delete()
        messages.success(request, _t("Role deleted."))
    return redirect("accounts:roles")
