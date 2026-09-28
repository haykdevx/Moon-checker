from django import forms
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _t, gettext_lazy as _

from .models import Role, User, alias_validator
from .permissions import PERMISSION_GROUPS, PERMISSIONS


class AliasField(forms.CharField):
    """Aliases are case-insensitive: normalise before the validators run."""

    def to_python(self, value):
        return (super().to_python(value) or "").strip().lower()


class LoginForm(forms.Form):
    username = forms.CharField(label=_("Nickname"), max_length=32,
                               widget=forms.TextInput(attrs={"autocomplete": "username", "autofocus": True}))
    password = forms.CharField(label=_("Password"), max_length=256,
                               widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}))


class TwoFactorForm(forms.Form):
    code = forms.CharField(label=_("Code from the app or a recovery code"), max_length=20,
                           widget=forms.TextInput(attrs={"autocomplete": "one-time-code", "inputmode": "numeric",
                                                         "autofocus": True}))


class SetPasswordForm(forms.Form):
    new_password = forms.CharField(label=_("New password"), max_length=256,
                                   widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))
    confirm = forms.CharField(label=_("Repeat the new password"), max_length=256,
                              widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean(self):
        data = super().clean()
        if data.get("new_password") and data.get("new_password") != data.get("confirm"):
            raise ValidationError(_t("The two passwords do not match."))
        if data.get("new_password"):
            password_validation.validate_password(data["new_password"], self.user)
        return data


class ChangePasswordForm(SetPasswordForm):
    current = forms.CharField(label=_("Current password"), max_length=256,
                              widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}))
    field_order = ["current", "new_password", "confirm"]

    def clean_current(self):
        if not self.user.check_password(self.cleaned_data["current"]):
            raise ValidationError(_t("Current password is wrong."))
        return self.cleaned_data["current"]


class InviteAcceptForm(SetPasswordForm):
    username = AliasField(label=_("Nickname (players will see it)"), max_length=32, validators=[alias_validator],
                               widget=forms.TextInput(attrs={"autocomplete": "username", "autofocus": True}))
    display_name = forms.CharField(label=_("Display name"), max_length=64, required=False)
    field_order = ["username", "display_name", "new_password", "confirm"]

    def clean_username(self):
        alias = self.cleaned_data["username"]
        if User.objects.filter(username=alias).exists():
            raise ValidationError(_t("This nickname is already taken."))
        return alias


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["display_name", "discord", "discord_webhook"]
        labels = {"display_name": _("Display name"), "discord": _("Discord"),
                  "discord_webhook": _("Discord webhook for your results")}
        widgets = {"discord_webhook": forms.TextInput(attrs={"placeholder": "https://discord.com/api/webhooks/…"})}


class ConfirmTotpForm(forms.Form):
    code = forms.CharField(label=_("6-digit code from the app"), max_length=8,
                           widget=forms.TextInput(attrs={"autocomplete": "one-time-code", "inputmode": "numeric"}))


class DisableTotpForm(forms.Form):
    password = forms.CharField(label=_("Password"), max_length=256,
                               widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}))
    code = forms.CharField(label=_("Current code from the app"), max_length=20)


class InviteForm(forms.Form):
    role = forms.ModelChoiceField(label=_("Role"), queryset=Role.objects.none())
    note = forms.CharField(label=_("Note"), max_length=100, required=False,
                           help_text=_("Who is this for? Only the team sees it."))
    hours = forms.TypedChoiceField(label=_("Valid for"), coerce=int, initial=48,
                                   choices=[(1, _("1 hour")), (24, _("24 hours")), (48, _("48 hours")),
                                            (168, _("7 days"))])

    def __init__(self, *args, roles=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["role"].queryset = roles


class MemberForm(forms.Form):
    role = forms.ModelChoiceField(label=_("Role"), queryset=Role.objects.none())
    display_name = forms.CharField(label=_("Display name"), max_length=64, required=False)
    is_active = forms.BooleanField(label=_("Account active"), required=False)

    def __init__(self, *args, roles=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["role"].queryset = roles


class RoleForm(forms.ModelForm):
    permissions = forms.MultipleChoiceField(label=_("Permissions"), required=False,
                                            widget=forms.CheckboxSelectMultiple)

    class Meta:
        model = Role
        fields = ["name", "rank", "color", "description", "permissions"]
        labels = {"name": _("Name"), "rank": _("Rank"), "color": _("Colour"), "description": _("Description")}
        widgets = {"color": forms.TextInput(attrs={"type": "color"})}

    def __init__(self, *args, actor=None, grantable=(), **kwargs):
        self.actor = actor
        super().__init__(*args, **kwargs)
        self.fields["permissions"].choices = [(c, PERMISSIONS[c]) for c in grantable]
        self.fields["rank"].help_text = _t("1–%(max)s. You can only manage roles below your own rank (%(own)s).") % {
            "max": actor.rank - 1, "own": actor.rank}
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
            raise ValidationError(_t("Rank must be between 1 and %(max)s.") % {"max": self.actor.rank - 1})
        return rank

    def clean_permissions(self):
        return sorted(set(self.cleaned_data["permissions"]) | set(self.hidden_permissions))
