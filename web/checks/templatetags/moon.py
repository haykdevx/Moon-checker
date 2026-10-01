"""Display helpers for outcomes, evidence kinds, statuses and decisions — in the member's language."""
from django import template
from django.utils.translation import get_language, gettext_lazy as _

register = template.Library()

# outcome -> (label, css tone)
OUTCOMES = {
    "VALIDATED_DETECTION": (_("Known cheat found"), "bad"),
    "REVIEW_REQUIRED": (_("Needs a look"), "review"),
    "UNSUPPORTED_CONFIGURATION": (_("System not supported"), "muted"),
    "INCOMPLETE_SCAN": (_("Check incomplete"), "incomplete"),
    # neutral, never green: "nothing reported" is not "clean" (the collection is not independently verified)
    "NO_EVIDENCE": (_("No evidence reported"), "none"),
    # checker < 1.1 (weighted score) — shown for what they are
    "CHEAT": (_("Cheat (old score)"), "bad"),
    "SUSPICIOUS": (_("Suspicious (old score)"), "review"),
    "INCONCLUSIVE": (_("Inconclusive (old)"), "incomplete"),
    "CLEAN": (_("Clean (old score)"), "none"),
}

OUTCOME_HELP = {
    "VALIDATED_DETECTION": _("A file on the PC matched a known cheat byte for byte. The decision is still yours."),
    "REVIEW_REQUIRED": _("The checker found traces worth a look with your own eyes. This is not a verdict — "
                         "you decide."),
    "UNSUPPORTED_CONFIGURATION": _("The player's system is not one the checker is built for, so the result "
                                   "is incomplete."),
    "INCOMPLETE_SCAN": _("Some required checks did not run (no administrator rights, an error or the time "
                         "limit). “Nothing found” cannot be concluded — ask the player to run it again."),
    "NO_EVIDENCE": _("Every required part reports that it ran and found nothing to look at. That is not proof "
                     "the PC is clean: what the checker collected is not independently verified."),
}

KINDS = {
    "DETECTION": (_("exact match"), "bad"),
    "INDICATOR": (_("indicator"), "review"),
    "CONCEALMENT": (_("hiding traces"), "review"),
    "CONFIGURATION": (_("system setting"), "muted"),
    "CONTEXT": (_("information"), "muted"),
}

KIND_HELP = {
    "DETECTION": _("The file matched a known cheat byte for byte."),
    "INDICATOR": _("A name, trace or content that matches a cheat rule. Check what the program really is."),
    "CONCEALMENT": _("Looks like traces were removed or hidden. It also happens after a reinstall or a "
                     "“cleaner” tool — ask the player."),
    "CONFIGURATION": _("A system setting that lowers trust in the report. Never a reason to ban on its own."),
    "CONTEXT": _("Background information; it does not affect the result."),
}

STATUSES = {
    "WAITING": _("Waiting for the player"),
    "CONNECTED": _("Checker connected"),
    "SCANNING": _("Checking"),
    "COMPLETED": _("Done"),
    "ABANDONED": _("Checker lost"),
    "EXPIRED": _("Code expired"),
    "CANCELLED": _("Cancelled"),
}

DECISIONS = {
    "CLEARED": _("Clean"),
    "BANNED": _("Ban"),
    "REVIEW": _("Needs a second look"),
    "RECHECK": _("Re-check"),
}


@register.filter
def outcome_label(value):
    return OUTCOMES.get(value, (value or "—", "muted"))[0]


@register.filter
def outcome_tone(value):
    return OUTCOMES.get(value, ("", "muted"))[1]


@register.filter
def outcome_help(value):
    return OUTCOME_HELP.get(value, "")


@register.filter
def kind_label(value):
    return KINDS.get(value, (value or "—", "muted"))[0]


@register.filter
def kind_tone(value):
    return KINDS.get(value, ("", "muted"))[1]


@register.filter
def kind_help(value):
    return KIND_HELP.get(value, "")


@register.filter
def status_label(value):
    return STATUSES.get(value, value or "—")


@register.filter
def decision_label(value):
    return DECISIONS.get(value, value or "—")


@register.filter
def loc(value):
    """Finding titles arrive as "Русский / English": the half in the member's language."""
    if not value or " / " not in value:
        return value
    ru, _sep, en = value.rpartition(" / ")
    return ru if (get_language() or "ru").startswith("ru") else en


@register.filter
def flag_text(flag):
    from checks.trust import flag_text as render
    return render(flag)


# one plain line per collector for the "How it checks" page; the catalogue keeps the technical detail
COLLECTORS = {
    "files": (_("Files on disk"), _("Looks for cheat files by name, exact hash and content, including renamed ones.")),
    "deleted": (_("Deleted files"), _("Finds cheat files that were deleted or renamed recently.")),
    "execution": (_("What was run"), _("Windows' own records of programs that were started (Prefetch and others).")),
    "amcache": (_("Program inventory"), _("Windows' list of programs and drivers that were ever on the PC.")),
    "persistence": (_("Autostart"), _("Programs that start with Windows or on a schedule.")),
    "kernel": (_("Drivers and kernel"), _("Loaded drivers, weakened driver protection and hidden objects.")),
    "environment": (_("Running programs and hardware"), _("Running processes, cheat windows, drivers and DMA "
                                                          "cheat hardware.")),
    "antiforensic": (_("Signs of cleaning"), _("Traces that logs or history were wiped shortly before the check.")),
    "cs2": (_("CS2 itself"), _("Whether the game's files were modified and what is loaded into the game.")),
    "cs2live": (_("Running game"), _("What is loaded into the running CS2 and what is drawn over it (needs the game open).")),
    "browser": (_("Browser history"), _("Visits to cheat sites. Only the matches leave the PC.")),
    "steam": (_("Steam accounts"), _("Accounts signed in on this PC and their VAC bans.")),
    "peripherals": (_("Macros and devices"), _("Macro software and USB devices used for scripts.")),
    "defender": (_("Windows Defender"), _("What the antivirus found and removed, and its exclusions.")),
    "dns": (_("DNS cache"), _("Cheat sites the PC looked up recently, whichever program did it.")),
    "linuxproc": (_("Linux processes"), _("Running processes and what is loaded into the game on Linux.")),
    "linuxfiles": (_("Linux files"), _("Cheat files in the home folder and temporary folders on Linux.")),
    "linuxhist": (_("Linux history"), _("Browser and terminal history matches on Linux.")),
    "linuxpersist": (_("Linux autostart"), _("Programs that start with the system on Linux.")),
}


@register.filter
def collector_name(module_id):
    return COLLECTORS.get(module_id, (module_id, ""))[0]


@register.filter
def collector_summary(module_id):
    return COLLECTORS.get(module_id, ("", ""))[1]
