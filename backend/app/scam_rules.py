"""ScamLens explainable message rules, production-oriented development version.

This module is deliberately conservative: patterns produce indicators, not proof
of fraud. Keep URL/network reputation checks in link_checker.py and combine these
signals in the API risk engine. No network calls or external dependencies.

Public interface retained for compatibility:
    check_message_rules(message) -> {flags, reasons, flag_count, disclaimer}

Strong flag IDs expected by the current ScamLens API are preserved:
    credential_request, payment_demand, threat_or_consequence,
    authority_plus_action
Other flags are contextual indicators and should generally lead to review, not
an automatic definitive scam verdict on their own.
"""
from __future__ import annotations

import re
from typing import Dict, List, Pattern, Union

DISCLAIMER = (
    "Rule flags are heuristic indicators, not proof of fraud. "
    "Legitimate messages can match these patterns; verify the sender and context."
)

# Each pattern is case-insensitive. Patterns aim to match explicit actions and
# combinations rather than broad keywords that would flag ordinary conversation.
RULES: Dict[str, dict] = {
    "credential_request": {
        "reason": "The message may be asking the recipient to disclose a sensitive credential.",
        "patterns": [
            r"\b(?:share|send|tell|provide|give|reveal|submit)\s+(?:me\s+)?(?:your\s+)?(?:otp|one[\s-]?time password|pin|password|passcode|cvv|cvc|security code)\b",
            r"\b(?:enter|type|reply with)\s+(?:your\s+)?(?:otp|one[\s-]?time password|pin|password|passcode|cvv|cvc|security code)\b",
            r"\b(?:otp|one[\s-]?time password|pin|password|passcode|cvv|cvc|security code)\s+(?:bhejo|batao|share karo|send karo)\b",
            r"\b(?:share|send|provide|give|submit)\s+(?:your\s+)?(?:bank details|account details|card details|net banking details)\b",
            r"\b(?:send|share|tell|provide)\s+(?:me\s+)?(?:your\s+)?(?:aadhaar|aadhar|pan)\s+(?:number|details|copy)\b",
            r"\b(?:otp bhejo|otp batao|otp share karo|apna otp bhejo|pin bhejo|password batao)\b",
        ],
    },
    "payment_demand": {
        "reason": "The message may be requesting an advance fee, transfer, or payment under suspicious circumstances.",
        "patterns": [
            r"\bpay\s+(?:(?:this|the|a|your)\s+)?(?:processing|registration|release|verification|customs|clearance|delivery|refundable|security|advance)\s+fee\b",
            r"\b(?:send|transfer|deposit|pay)\s+(?:the\s+|your\s+)?(?:money|funds|fee|fees|commission|deposit|payment)\b",
            r"\b(?:processing fee|release fee|registration fee|customs fee|clearance fee|advance fee|security deposit)\b",
            r"\bpay\s+(?:this\s+|the\s+)?(?:penalty|fine|tax)\b",
            r"\b(?:advance payment|pay now|payment required to release|fee to receive your prize)\b",
            r"\b(?:paise bhejo|paisa bhejo|abhi payment karo|advance jama karo|registration fee bhejo)\b",
        ],
    },
    "threat_or_consequence": {
        "reason": "The message threatens a serious consequence or loss of access.",
        "patterns": [
            r"\b(?:account|card|wallet|sim|number)\s+(?:will be|may be|is being)\s+(?:blocked|frozen|suspended|deactivated|disconnected|closed)\b",
            r"\b(?:unless|otherwise|or else)\b.{0,80}\b(?:blocked|suspended|disconnected|arrested|legal action|penalty)\b",
            r"\b(?:you will be arrested|arrest warrant|legal action will be taken|police case will be filed|account block ho jayega|sim band ho jayega|case darj hoga)\b",
            r"\b(?:pay|send|share|provide|verify)\b.{0,70}\b(?:or your account|or sim|to avoid arrest|to prevent suspension)\b",
        ],
    },
    "urgent_action": {
        "reason": "The message pressures the recipient to act immediately.",
        "patterns": [
            r"\b(?:act now|immediately|urgent(?:ly)?|within\s+\d+\s+minutes?|call now|call immediately|last warning|final notice|abhi karo|turant|jaldi karo)\b",
        ],
    },
    "authority_claim": {
        "reason": "The message appears to invoke a government, financial, telecom, or other authority.",
        "patterns": [
            r"\bwe are (?:your|the) bank\b",
            r"\b(?:we are from|calling from|message from|this is)\s+(?:the\s+)?(?:tax|income tax|government|police|customs|immigration|telecom|bank|court|cyber crime)\s+(?:department|office|team|authority)\b",
            r"\b(?:tax department|income tax department|government officer|foreign officer|police officer|customs officer|immigration officer|telecom department|cyber crime department|bank officer)\b",
            r"\b(?:sarkari yojana|sarkari scheme|government scheme|government contract|tax refund|official compensation)\b",
            r"\b(?:bank se bol raha|bank se bol rahi|police se bol raha|department se bol raha)\b",
        ],
    },
    "remote_access_request": {
        "reason": "The message may be asking the recipient to install or use remote-control software.",
        "patterns": [
            # Explicit installation or launch requests for remote-control tools.
            r"\b(?:install|download|run|open)\b.{0,90}\b(?:remote[\s-]?access|remote[\s-]?control|screen[\s-]?sharing)\s+(?:software|app|application|tool|program)\b",
            r"\b(?:install|download|run|open)\b.{0,60}\b(?:anydesk|teamviewer|rustdesk|ultraviewer|zoho assist|splashtop)\b",
            r"\b(?:anydesk|teamviewer|rustdesk|ultraviewer|zoho assist|splashtop)\b.{0,90}\b(?:give|grant|allow|enable|provide)\b.{0,40}\b(?:access|control|permission|screen)\b",
            r"\b(?:remote[\s-]?access software|remote[\s-]?control app|screen[\s-]?sharing tool)\b.{0,90}\b(?:repair|fix|support|technician|agent|refund|virus|infected|security issue)\b",
            r"\b(?:computer|device|laptop|system)\b.{0,70}\b(?:infected|compromised|has a virus)\b.{0,100}\b(?:install|download|remote[\s-]?access|anydesk|teamviewer)\b",
        ],
    },
    "money_mule_request": {
        "reason": "The message may be asking the recipient to move money or provide banking access for someone else.",
        "patterns": [
            r"\b(?:help|assist)\b.{0,55}\b(?:move|moving|transfer|transferring|route|routing|receive|receiving)\b.{0,35}\b(?:money|funds|payment)\b",
            r"\b(?:needs?|need|asks?|asking)\b.{0,35}\b(?:your )?help\b.{0,35}\b(?:move|moving|transfer|transferring|route|routing)\b.{0,30}\b(?:money|funds)\b",
            r"\b(?:move|moving|transfer|transferring|route|routing)\b.{0,40}\b(?:money|funds)\b.{0,90}\b(?:bank details|account details|your account|send your bank)\b",
            r"\b(?:send|share|provide)\b.{0,35}\b(?:your )?(?:bank details|account details)\b.{0,90}\b(?:move|moving|transfer|transferring|foreign officer|officer|inheritance|commission)\b",
            r"\buse your (?:bank )?account to (?:receive|transfer|move|route)\b",
            r"\breceive money for me and transfer\b",
            r"\b(?:foreign|overseas) officer\b.{0,100}\b(?:money|funds|bank details|account details|transfer)\b",
        ],
    },
    "advance_fee_scam": {
        "reason": "The message links a promised benefit, prize, inheritance, job, parcel, or relationship to an upfront fee.",
        "patterns": [
            r"\b(?:inheritance|prize|lottery|grant|compensation|refund|parcel|job|visa|contract)\b.{0,120}\b(?:fees?|tax|commission|payment|deposit)\b",
            r"\b(?:fees?|tax|commission|payment|deposit)\b.{0,120}\b(?:inheritance|prize|lottery|grant|compensation|refund|parcel|job|visa|contract)\b",
            r"\b(?:send|pay|transfer|asks? for|request(?:s|ed)?)\b.{0,60}\b(?:visa fees?|legal fees?|customs fees?|release fees?)\b",
            r"\b(?:visa|inheritance|parcel|prize|grant)\b.{0,100}\b(?:asks? for|request(?:s|ed)?|send|pay|transfer)\b.{0,60}\b(?:money|fees?|payment|deposit)\b",
            r"\b(?:love|romantic|relationship|first meeting|meet me)\b.{0,100}\b(?:asks? for|request(?:s|ed)?|send|pay|transfer)\b.{0,50}\b(?:money|visa fees?|travel fees?|ticket|deposit)\b",
            r"\b(?:asks? for|request(?:s|ed)?|send|pay|transfer)\b.{0,50}\b(?:money|visa fees?|travel fees?|ticket|deposit)\b.{0,100}\b(?:love|romantic|relationship|first meeting|meet me)\b",
        ],
    },
    "investment_claim": {
        "reason": "The message may be promoting unusually high or guaranteed investment returns.",
        "patterns": [
            r"\bguaranteed\s+(?:returns?|profit|income)\b",
            r"\bearn\s+\d{1,3}\s*(?:%|percent)\b.{0,50}\b(?:every week|daily|per day|risk[- ]free)\b",
            r"\b(?:double|triple)\s+your\s+(?:money|investment)\b",
        ],
    },
}

# A strong authority flag requires both an authority indicator and a concrete
# suspicious action/request. A bare mention of an authority is not enough.
AUTHORITY_ACTION_PATTERNS = [
    r"\b(?:click|open)\b.{0,25}\b(?:link|here)\b",
    r"\b(?:call|contact)\b.{0,25}\b(?:now|immediately|this number|our agent)\b",
    r"\b(?:verify|update|confirm)\b.{0,50}\b(?:account|kyc|identity|bank details|otp|password)\b",
    r"\b(?:pay|send|transfer|provide|share|release|move)\b.{0,90}\b(?:penalty|fine|fee|money|funds|bank details|account details|otp|payment)\b",
    r"\b(?:send|share|provide)\b.{0,35}\b(?:your )?(?:bank details|account details)\b",
    r"\b(?:move|moving|transfer|transferring)\b.{0,35}\b(?:money|funds)\b",
    r"\b(?:registration fee|processing fee|unofficial commission)\b",
    r"\b(?:sarkari scheme|government scheme|government contract)\b.{0,100}\b(?:fee|fees|commission|payment|money|funds)\b",
    r"\b(?:otp bhejo|abhi payment karo|link par click karo|bank details bhejo)\b",
]

# Protective language is used to suppress only the matching credential-request
# indicator when the message reads as advice. Other independently matched signals
# are not erased. This avoids blanket whitelisting a whole message.
PROTECTIVE_PATTERNS = [
    r"\b(?:never|do not|don't|dont|should not|should never|avoid)\s+(?:share|send|give|tell|reveal|provide)\b.{0,45}\b(?:otp|one[\s-]?time password|pin|password|cvv|bank details|card details)\b",
    r"\b(?:never share|do not share|don't share|dont share)\b.{0,30}\b(?:otp|pin|password|cvv|bank details|card details)\b",
    r"\b(?:kisi ko|kisi ke saath)\b.{0,35}\b(?:otp|pin|password)\b.{0,25}\b(?:mat batao|share mat karo|mat bhejo)\b",
    r"\b(?:bank|police|government|cyber crime)\s+(?:will never|never)\s+(?:ask|request)\b.{0,45}\b(?:otp|password|pin|bank details)\b",
]


def _compile(patterns: List[str]) -> List[Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


_COMPILED_RULES = {
    key: _compile(value["patterns"]) for key, value in RULES.items()
}
_COMPILED_AUTHORITY_ACTION = _compile(AUTHORITY_ACTION_PATTERNS)
_COMPILED_PROTECTIVE = _compile(PROTECTIVE_PATTERNS)


def _matches(text: str, patterns: List[Pattern[str]]) -> bool:
    return any(pattern.search(text) is not None for pattern in patterns)


def check_message_rules(message: Union[str, None]) -> dict:
    """Return stable, explainable rule flags for one message.

    This function never returns a definitive scam verdict. The API risk engine
    should treat credential/payment/threat/authority-combination flags as strong
    indicators and contextual flags as review signals unless corroborated.
    """
    if message is None:
        text = ""
    else:
        text = re.sub(r"\s+", " ", str(message)).strip()

    flags: List[str] = []
    reasons: List[str] = []

    if not text:
        return {
            "flags": flags,
            "reasons": reasons,
            "flag_count": 0,
            "disclaimer": DISCLAIMER,
        }

    matched = {
        rule_id: _matches(text, patterns)
        for rule_id, patterns in _COMPILED_RULES.items()
    }

    # Suppress credential_request only for recognizable protective advice. Do not
    # erase threats, payment requests, or other independently detected signals.
    if matched["credential_request"] and _matches(text, _COMPILED_PROTECTIVE):
        matched["credential_request"] = False

    def add(flag_id: str, reason: str) -> None:
        if flag_id not in flags:
            flags.append(flag_id)
            reasons.append(reason)

    # These IDs are consumed by the existing ScamLens risk engine.
    for rule_id in (
        "credential_request",
        "payment_demand",
        "threat_or_consequence",
        "urgent_action",
    ):
        if matched.get(rule_id):
            add(rule_id, RULES[rule_id]["reason"])

    authority_action = _matches(text, _COMPILED_AUTHORITY_ACTION)
    if matched["authority_claim"] and (
        authority_action
        or matched["credential_request"]
        or matched["payment_demand"]
        or matched["threat_or_consequence"]
        or matched["money_mule_request"]
    ):
        add(
            "authority_plus_action",
            "Authority-related language is combined with a suspicious request or action.",
        )

    # Contextual signals are intentionally separate from the API's strong flags.
    for rule_id in (
        "remote_access_request",
        "money_mule_request",
        "advance_fee_scam",
        "investment_claim",
    ):
        if matched.get(rule_id):
            add(rule_id, RULES[rule_id]["reason"])

    return {
        "flags": flags,
        "reasons": reasons,
        "flag_count": len(flags),
        "disclaimer": DISCLAIMER,
    }


if __name__ == "__main__":
    examples = [
        ("Your SIM will be disconnected unless you share your OTP with our agent.", True),
        ("Your computer is infected. Install remote access software for free repair.", True),
        ("A foreign officer needs your help moving money. Send your bank details.", True),
        ("A stranger offers to share an inheritance with you but asks for legal fees in advance.", True),
        ("Sarkari scheme ka paisa release karne ke liye abhi registration fee bhejne ko keh rahe hain.", True),
        ("A person offers a government contract and asks for an unofficial commission before sharing the paperwork.", True),
        ("Never share your OTP with anyone, even if they claim to be from your bank.", False),
        ("The government website explains how to check your application status.", False),
        ("Our IT team can help with remote access after you open an approved support ticket.", False),
        ("Your exam form was submitted successfully.", False),
    ]
    for message, expected_suspicious in examples:
        result = check_message_rules(message)
        print("\nMessage:", message)
        print("Expected suspicious:", expected_suspicious)
        print("Flags:", result["flags"])
        print("Reasons:", result["reasons"])
