"""ScamLens explainable message-pattern rules.

Rules are heuristic indicators, not definitive scam verdicts.
"""
import re

RULES = {
    "credential_request": {
        "reason": "The message may be asking for a sensitive credential.",
        "patterns": [
            r"\botp\b", r"\bone[\s-]?time password\b", r"\bpin\b",
            r"\bpassword\b", r"\bcvv\b",
            r"\bshare your (?:login|banking|card) details\b",
            r"\botp bhej(?:o|iye)\b", r"\bpin bhej(?:o|iye)\b",
            r"\bpassword bata(?:o|iye)\b", r"\botp share karo\b",
        ],
    },
    "payment_demand": {
        "reason": "The message may be demanding a fee or advance payment.",
        "patterns": [
            r"\bprocessing fee\b", r"\brelease fee\b",
            r"\bpay (?:a|the|your)?\s*(?:fee|deposit|advance)\b",
            r"\badvance payment\b", r"\bsecurity deposit\b",
            r"\btransfer (?:the )?money\b", r"\bpay now\b",
            r"\babhi payment karo\b", r"\bpaise bhej(?:o|iye)\b",
            r"\badvance jama karo\b",
            r"\b(?:₹|rs\.?|inr)\s?\d[\d,]*(?:\.\d{1,2})?\b",
        ],
    },
    "threat_or_consequence": {
        "reason": "The message mentions a threat or serious consequence.",
        "patterns": [
            r"\baccount (?:will be|is being) blocked\b",
            r"\baccount (?:blocked|frozen|suspended)\b",
            r"\bsim (?:will be|is being) disconnected\b",
            r"\barrest(?:ed)?\b", r"\blegal action\b", r"\bpolice case\b",
            r"\baccount block ho jayega\b", r"\bsim band ho jayega\b",
            r"\barrest kar liya jayega\b", r"\bcase darj hoga\b",
        ],
    },
    "authority_claim": {
        "reason": "The message claims to represent an authority or official service.",
        "patterns": [
            r"\b(?:your )?bank\b", r"\bpolice\b", r"\bgovernment\b",
            r"\bincome tax\b", r"\bcourier\b", r"\bgovernment officer\b",
            r"\bbank se bol raha\b", r"\bpolice department\b",
            r"\btelecom department\b",
        ],
    },
    "urgent_action": {
        "reason": "The message pressures the recipient to act quickly.",
        "patterns": [
            r"\bact now\b", r"\bimmediately\b", r"\burgent(?:ly)?\b",
            r"\bwithin \d+ minutes?\b", r"\bcall now\b",
            r"\bcall immediately\b", r"\babhi karo\b",
            r"\bturant\b", r"\bjaldi karo\b", r"\blast warning\b",
        ],
    },
}

ACTION_PATTERNS = [
    r"https?://", r"\bwww\.", r"\bclick (?:here|the link)\b",
    r"\bcall (?:now|immediately|this number)\b",
    r"\bcontact us immediately\b", r"\blink par click karo\b",
    r"\babhi call karo\b",
]

# Common protective/advisory language should not be treated as a request
# merely because it mentions credentials. This is a conservative exception list.
PROTECTIVE_PATTERNS = [
    r"\bnever share\b", r"\bdo not share\b", r"\bdon't share\b",
    r"\bnever give\b", r"\bdo not give\b", r"\bdon't give\b",
    r"\bnever tell\b", r"\bdo not tell\b", r"\bdon't tell\b",
    r"\bavoid sharing\b", r"\bshould not share\b",
    r"\bshould never share\b", r"\bnot to share\b",
    r"\bkisi ko (?:bhi )?(?:otp|pin|password) mat batao\b",
    r"\botp kisi ke saath share mat karo\b",
]

def _matches(text, patterns):
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)

def check_message_rules(message):
    text = re.sub(r"\s+", " ", (message or "").strip())
    if not text:
        return {
            "flags": [], "reasons": [], "flag_count": 0,
            "disclaimer": "Rule flags are heuristic indicators, not proof of fraud."
        }

    protective = _matches(text, PROTECTIVE_PATTERNS)
    matched = {
        rule_id: _matches(text, rule["patterns"])
        for rule_id, rule in RULES.items()
    }

    # If the message is clearly protective advice and has no separate imperative
    # credential demand, suppress credential_request. Other independent signals
    # remain eligible to be reported.
    if protective:
        matched["credential_request"] = False

    flags, reasons = [], []

    def add(flag_id, reason):
        if flag_id not in flags:
            flags.append(flag_id)
            reasons.append(reason)

    for rule_id in (
        "credential_request", "payment_demand",
        "threat_or_consequence", "urgent_action"
    ):
        if matched[rule_id]:
            add(rule_id, RULES[rule_id]["reason"])

    action_found = _matches(text, ACTION_PATTERNS)
    if matched["authority_claim"] and (
        action_found or matched["credential_request"]
        or matched["payment_demand"] or matched["threat_or_consequence"]
    ):
        add(
            "authority_plus_action",
            "An authority claim is combined with a request, link, payment, or threat."
        )

    return {
        "flags": flags,
        "reasons": reasons,
        "flag_count": len(flags),
        "disclaimer": (
            "Rule flags are heuristic indicators, not proof of fraud. "
            "Legitimate messages can match these patterns."
        )
    }
