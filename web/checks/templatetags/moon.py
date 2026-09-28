"""Display helpers for outcomes and evidence kinds (v2) and legacy v1 verdicts."""
from django import template

register = template.Library()

# outcome -> (label, css tone)
OUTCOMES = {
    "VALIDATED_DETECTION": ("Validated detection", "bad"),
    "REVIEW_REQUIRED": ("Review required", "review"),
    "UNSUPPORTED_CONFIGURATION": ("Unsupported configuration", "muted"),
    "INCOMPLETE_SCAN": ("Incomplete scan", "incomplete"),
    "NO_EVIDENCE": ("No evidence found", "ok"),
    # checker < 1.1 (weighted score) — shown for what they are
    "CHEAT": ("Cheat (legacy score)", "bad"),
    "SUSPICIOUS": ("Suspicious (legacy score)", "review"),
    "INCONCLUSIVE": ("Inconclusive (legacy)", "incomplete"),
    "CLEAN": ("Clean (legacy score)", "ok"),
}

OUTCOME_HELP = {
    "VALIDATED_DETECTION": "A known cheat file was identified by its exact hash. The decision is still yours.",
    "REVIEW_REQUIRED": "Indicators need a human look. This is not a cheating verdict on its own.",
    "UNSUPPORTED_CONFIGURATION": "The player's OS or architecture is outside what the checker is validated on.",
    "INCOMPLETE_SCAN": "Required collectors failed or lacked rights, so “nothing found” cannot be concluded.",
    "NO_EVIDENCE": "Every required collector completed and found nothing to review. Not proof the PC is clean.",
}

KINDS = {
    "DETECTION": ("Exact detection", "bad"),
    "INDICATOR": ("Indicator", "review"),
    "CONCEALMENT": ("Concealment", "review"),
    "CONFIGURATION": ("Configuration", "muted"),
    "CONTEXT": ("Context", "muted"),
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
