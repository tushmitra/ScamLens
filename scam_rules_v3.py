"""ScamLens explainable message-pattern rules, v3.

These rules are heuristic indicators, not definitive scam verdicts.
The module avoids treating protective advice as a credential demand and
requires an explicit authority/action combination for that specific flag.
"""
import re

RULES = {
    "credential_request": {
        "reason": "The message may be asking for a sensitive credential.",
        "patterns": [
            r"\bshare (?:your )?(?:otp|one[\s-]?time password|pin|password|cvv)\b",
            r"\b(?:send|tell|provide|enter|submit) (?:me )?(?:your )?(?:otp|pin|password|cvv)\b",
            r"\b(?:enter|submit) (?:the )?(?:otp|pin|password|cvv)\b",
            r"\bverify (?:your )?(?:account|identity).{0,50}\b(?:otp|pin|password|cvv)\b",
            r"\botp bhej(?:o|iye)\b",
            r"\bpin bhej(?:o|iye)\b",
            r"\bpassword bata(?:o|iye)\b",
            r"\botp share karo\b",
            r"\bapna otp bhejo\b",
            r"\b(?:otp|pin|password|cvv)\s+(?:bhejo|batao|share karo)\b",
        ],
    },
    "payment_demand": {
        "reason": "The message may be demanding a fee or advance payment.",
        "patterns": [
            r"\bpay (?:a |the |your )?(?:processing )?fee\b",
            r"\bprocessing fee\b",
            r"\brelease fee\b",
            r"\bpay (?:a |the |your )?(?:security )?deposit\b",
            r"\badvance payment\b",
            r"\bsecurity deposit\b",
            r"\btransfer (?:the )?money\b",
            r"\bpay now\b",
            r"\babhi payment karo\b",
            r"\bpaise bhej(?:o|iye)\b",
            r"\badvance jama karo\b",
        ],
    },
    "threat_or_consequence": {
        "reason": "The message mentions a threat or serious consequence.",
        "patterns": [
            r"\baccount (?:will be|is being) blocked\b",
            r"\baccount (?:blocked|frozen|suspended)\b",
            r"\bsim (?:will be|is being) disconnected\b",
            r"\byou will be arrested\b",
            r"\barrest kar liya jayega\b",
            r"\blegal action will be taken\b",
            r"\bpolice case(?: will be)?\b",
            r"\baccount block ho jayega\b",
            r"\bsim band ho jayega\b",
            r"\bcase darj hoga\b",
        ],
    },
    "authority_claim": {
        "reason": "The message claims to represent an authority or official service.",
        "patterns": [
            r"\b(?:we are|this is|calling from|message from)\s+(?:your )?(?:bank|police|government|income tax|courier)\b",
            r"\b(?:official|authorized)\s+(?:bank|police|government|courier)\b",
            r"\b(?:bank|police|government|income tax|courier)\s+(?:department|officer|support team)\b",
            r"\bbank se bol raha(?: hoon)?\b",
            r"\btelecom department\b",
        ],
    },
    "urgent_action": {
        "reason": "The message pressures the recipient to act quickly.",
        "patterns": [
            r"\bact now\b",
            r"\bimmediately\b",
            r"\burgent(?:ly)?\b",
            r"\bwithin \d+ minutes?\b",
            r"\bcall now\b",
            r"\bcall immediately\b",
            r"\babhi karo\b",
            r"\bturant\b",
            r"\bjaldi karo\b",
            r"\blast warning\b",
        ],
    },
}

# This is intentionally narrower than merely finding a URL or the word "call".
AUTHORITY_ACTION_PATTERNS = [
    r"\bclick (?:here|the link)\b",
    r"\bcall (?:now|immediately|this number)\b",
    r"\bcontact us immediately\b",
    r"\bverify (?:your )?(?:account|kyc|identity) (?:now|immediately|here)\b",
    r"\bupdate (?:your )?(?:kyc|account details) (?:now|immediately|here)\b",
    r"\blink par click karo\b",
    r"\babhi call karo\b",
    r"\b(?:pay|transfer) (?:now|immediately)\b",
]

PROTECTIVE_PATTERNS = [
    r"\bnever share\b",
    r"\bdo not share\b",
    r"\bdon't share\b",
    r"\bnever give\b",
    r"\bdo not give\b",
    r"\bdon't give\b",
    r"\bnever tell\b",
    r"\bdo not tell\b",
    r"\bdon't tell\b",
    r"\bavoid sharing\b",
    r"\bshould not share\b",
    r"\bshould never share\b",
    r"\bnot to share\b",
    r"\bkisi ko (?:bhi )?(?:otp|pin|password) mat batao\b",
    r"\botp kisi ke saath share mat karo\b",
]

def _matches(text, patterns):
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)

def check_message_rules(message):
    text = re.sub(r"\s+", " ", (message or "").strip())
    if not text:
        return {
            "flags": [],
            "reasons": [],
            "flag_count": 0,
            "disclaimer": "Rule flags are heuristic indicators, not proof of fraud."
        }

    protective = _matches(text, PROTECTIVE_PATTERNS)
    matched = {
        rule_id: _matches(text, rule["patterns"])
        for rule_id, rule in RULES.items()
    }

    # Protective advice should not itself be treated as a credential request.
    if protective:
        matched["credential_request"] = False

    flags, reasons = [], []

    def add(flag_id, reason):
        if flag_id not in flags:
            flags.append(flag_id)
            reasons.append(reason)

    for rule_id in (
        "credential_request",
        "payment_demand",
        "threat_or_consequence",
        "urgent_action",
    ):
        if matched[rule_id]:
            add(rule_id, RULES[rule_id]["reason"])

    authority_action = _matches(text, AUTHORITY_ACTION_PATTERNS)
    if matched["authority_claim"] and (
        authority_action
        or matched["credential_request"]
        or matched["payment_demand"]
        or matched["threat_or_consequence"]
    ):
        add(
            "authority_plus_action",
            "An explicit authority claim is combined with a suspicious request or action."
        )

    return {
        "flags": flags,
        "reasons": reasons,
        "flag_count": len(flags),
        "disclaimer": (
            "Rule flags are heuristic indicators, not proof of fraud. "
            "Legitimate messages can match these patterns."
        ),
    }
