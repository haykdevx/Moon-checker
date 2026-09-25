import hashlib
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from checks.models import TrustedBuild


class Command(BaseCommand):
    help = "Registers an official checker build (file path or sha256) as trusted."

    def add_arguments(self, parser):
        parser.add_argument("file_or_hash")
        parser.add_argument("--label", required=True)

    def handle(self, file_or_hash, label, **opts):
        value = file_or_hash.strip().lower()
        path = Path(file_or_hash)
        if path.is_file():
            value = hashlib.sha256(path.read_bytes()).hexdigest()
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise CommandError("Pass an existing file or a 64-char sha256.")
        obj, created = TrustedBuild.objects.update_or_create(sha256=value, defaults={"label": label[:80]})
        self.stdout.write(f"{'added' if created else 'updated'} trusted build {obj.label}: {obj.sha256}")
