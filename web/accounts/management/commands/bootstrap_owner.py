import secrets

from django.core.management.base import BaseCommand, CommandError

from accounts.models import Role, User
from accounts.permissions import OWNER_SLUG


class Command(BaseCommand):
    help = "Creates the first owner account with a random one-time password (must be changed at first sign-in)."

    def add_arguments(self, parser):
        parser.add_argument("alias")
        parser.add_argument("--reset", action="store_true",
                            help="If the alias exists, issue a new one-time password and clear its 2FA.")

    def handle(self, alias, reset=False, **opts):
        role = Role.objects.filter(slug=OWNER_SLUG).first()
        if role is None:
            raise CommandError("Roles are missing; run migrate first.")
        password = secrets.token_urlsafe(12)
        user = User.objects.filter(username=alias.lower()).first()
        if user is not None and not reset:
            raise CommandError(f"{alias} already exists (use --reset to recover access).")
        if user is None:
            user = User.objects.create_user(alias, password, role=role, must_change_password=True)
        else:
            user.set_password(password)
            user.role, user.is_active, user.must_change_password = role, True, True
            user.totp_enabled, user.totp_secret = False, ""
            user.session_epoch += 1
            user.save()
            user.recovery_codes.all().delete()
        from core.audit import record
        record(None, "owner.bootstrapped", user.username, actor=None, reset=reset)
        self.stdout.write(self.style.SUCCESS(f"Owner '{user.username}' ready."))
        self.stdout.write(f"One-time password: {password}")
        self.stdout.write("You will be asked to change it and set up 2FA at first sign-in.")
