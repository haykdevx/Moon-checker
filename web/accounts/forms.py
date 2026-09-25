from django import forms
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError

from .models import Role, User, alias_validator
from .permissions import PERMISSION_GROUPS, PERMISSIONS


class AliasField(forms.CharField):
    """Aliases are case-insensitive: normalise before the validators run."""

    def to_python(self, value):
        return (super().to_python(value) or "").strip().lower()


class LoginForm(forms.Form):
    username = forms.CharField(label="Alias", max_length=32,
                               widget=forms.TextInput(attrs={"autocomplete": "username", "autofocus": True}))
    password = forms.CharField(max_length=256, widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}))


class TwoFactorForm(forms.Form):
    code = forms.CharField(label="Authenticator or recovery code", max_length=20,
                           widget=forms.TextInput(attrs={"autocomplete": "one-time-code", "inputmode": "numeric",
                                                         "autofocus": True}))


class SetPasswordForm(forms.Form):
    new_password = forms.CharField(label="New password", max_length=256,
                                   widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))
    confirm = forms.CharField(label="Repeat new password", max_length=256,
                              widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean(self):
        data = super().clean()
        if data.get("new_password") and data.get("new_password") != data.get("confirm"):
            raise ValidationError("The two passwords do not match.")
        if data.get("new_password"):
            password_validation.validate_password(data["new_password"], self.user)
        return data


class ChangePasswordForm(SetPasswordForm):
    current = forms.CharField(label="Current password", max_length=256,
                              widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}))
    field_order = ["current", "new_password", "confirm"]

    def clean_current(self):
        if not self.user.check_password(self.cleaned_data["current"]):
            raise ValidationError("Current password is wrong.")
        return self.cleaned_data["current"]


class InviteAcceptForm(SetPasswordForm):
    username = AliasField(label="Alias (players will see this)", max_length=32, validators=[alias_validator],
                               widget=forms.TextInput(attrs={"autocomplete": "username", "autofocus": True}))
    display_name = forms.CharField(max_length=64, required=False)
    field_order = ["username", "display_name", "new_password", "confirm"]

    def clean_username(self):
        alias = self.cleaned_data["username"]
        if User.objects.filter(username=alias).exists():
            raise ValidationError("This alias is already taken.")
        return alias


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["display_name", "discord", "discord_webhook"]
        widgets = {"discord_webhook": forms.TextInput(attrs={"placeholder": "https://discord.com/api/webhooks/…"})}


class ConfirmTotpForm(forms.Form):
    code = forms.CharField(label="6-digit code from the app", max_length=8,
                           widget=forms.TextInput(attrs={"autocomplete": "one-time-code", "inputmode": "numeric"}))


class DisableTotpForm(forms.Form):
    password = forms.CharField(max_length=256, widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}))
    code = forms.CharField(label="Current authenticator code", max_length=20)


class InviteForm(forms.Form):
    role = forms.ModelChoiceField(queryset=Role.objects.none())
    note = forms.CharField(max_length=100, required=False, help_text="Who is this for? Only visible to the team.")
    hours = forms.TypedChoiceField(label="Valid for", coerce=int, initial=48,
                                   choices=[(1, "1 hour"), (24, "24 hours"), (48, "48 hours"), (168, "7 days")])

    def __init__(self, *args, roles=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["role"].queryset = roles


class MemberForm(forms.Form):
    role = forms.ModelChoiceField(queryset=Role.objects.none())
    display_name = forms.CharField(max_length=64, required=False)
    is_active = forms.BooleanField(label="Account active", required=False)

    def __init__(self, *args, roles=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["role"].queryset = roles


class RoleForm(forms.ModelForm):
    permissions = forms.MultipleChoiceField(required=False, widget=forms.CheckboxSelectMultiple)

    class Meta:
        model = Role
        fields = ["name", "rank", "color", "description", "permissions"]
        widgets = {"color": forms.TextInput(attrs={"type": "color"})}

    def __init__(self, *args, actor=None, grantable=(), **kwargs):
        self.actor = actor
        super().__init__(*args, **kwargs)
        self.fields["permissions"].choices = [(c, PERMISSIONS[c]) for c in grantable]
        self.fields["rank"].help_text = f"1–{actor.rank - 1}. You can only manage roles below your own rank ({actor.rank})."
        self.permission_groups = [
            (title, [c for c in codes if c in grantable]) for title, codes in PERMISSION_GROUPS
        ]
        if self.instance.pk:
            # keep permissions the editor cannot see (they hold them not) untouched
            self.hidden_permissions = [c for c in self.instance.permissions if c not in grantable]
        else:
            self.hidden_permissions = []

    def clean_rank(self):
        rank = self.cleaned_data["rank"]
        if not 1 <= rank < self.actor.rank:
            raise ValidationError(f"Rank must be between 1 and {self.actor.rank - 1}.")
        return rank

    def clean_permissions(self):
        return sorted(set(self.cleaned_data["permissions"]) | set(self.hidden_permissions))
