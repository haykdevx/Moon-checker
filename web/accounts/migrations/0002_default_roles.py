from django.db import migrations

from accounts.permissions import DEFAULT_ROLES


def create_roles(apps, schema_editor):
    Role = apps.get_model("accounts", "Role")
    for slug, name, rank, color, perms, description in DEFAULT_ROLES:
        Role.objects.get_or_create(slug=slug, defaults={
            "name": name, "rank": rank, "color": color, "permissions": list(perms),
            "description": description, "is_system": True})


class Migration(migrations.Migration):
    dependencies = [("accounts", "0001_initial")]
    operations = [migrations.RunPython(create_roles, migrations.RunPython.noop)]
