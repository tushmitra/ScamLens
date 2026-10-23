from helpers import BACKEND  # noqa: F401

from app.scam_rules import check_message_rules


def flags(message):
    return check_message_rules(message)["flags"]


def test_empty_and_none():
    for value in (None, "", "   \n\t "):
        result = check_message_rules(value)
        assert result["flags"] == [] and result["flag_count"] == 0
        assert "not proof of fraud" in result["disclaimer"]


def test_credential_request_english_and_hinglish():
    assert "credential_request" in flags("Please share your OTP to verify your bank account.")
    assert "credential_request" in flags("Send me your password and CVV now")
    assert "credential_request" in flags("OTP bhejo abhi")
    assert "credential_request" in flags("Apna otp bhejo turant")


def test_protective_advice_is_not_a_credential_request():
    assert "credential_request" not in flags("Never share your OTP or password with anyone.")
    assert "credential_request" not in flags("Never share your OTP with anyone, even if they claim to be from your bank.")
    assert "credential_request" not in flags("Bank OTP kisi ke saath share mat karna.")
    assert "credential_request" not in flags("Your SBI OTP is 582941. Do not share it with anyone.")


def test_protective_language_does_not_hide_other_signals():
    result = flags("Never share your OTP. But pay the processing fee now or your account will be blocked.")
    assert "payment_demand" in result and "threat_or_consequence" in result


def test_payment_demand():
    assert "payment_demand" in flags("You won a prize. Pay a processing fee to claim it.")
    assert "payment_demand" in flags("Transfer the money immediately to this account")
    assert "payment_demand" in flags("Registration fee bhejo abhi")


def test_ordinary_payment_talk_is_not_flagged():
    assert flags("Your electricity bill of Rs 850 has been paid successfully.") == []
    assert flags("Your UPI payment was successful. Check your bank statement for details.") == []


def test_threat_or_consequence():
    assert "threat_or_consequence" in flags("Your SIM will be disconnected unless you share your OTP with our agent.")
    assert "threat_or_consequence" in flags("Your account will be blocked today")
    assert "threat_or_consequence" in flags("Account block ho jayega, turant action lo")


def test_urgent_action_is_a_supporting_flag_only():
    assert flags("Please call me urgently when you reach") == ["urgent_action"]
    assert flags("Meeting moved. Reply immediately if you cannot attend.") == ["urgent_action"]


def test_authority_alone_is_not_enough():
    assert "authority_plus_action" not in flags("I work at a bank and can explain savings accounts.")
    assert "authority_plus_action" not in flags("The government website explains how to check your application status.")
    assert "authority_plus_action" not in flags("Please share your OTP to verify your bank account.")


def test_authority_plus_action():
    assert "authority_plus_action" in flags("We are your bank. Click here to verify your account now.")
    assert "authority_plus_action" in flags("Income tax department: pay this penalty or face legal action.")
    assert "authority_plus_action" in flags(
        "Sarkari scheme ka paisa release karne ke liye abhi registration fee bhejne ko keh rahe hain."
    )


def test_contextual_flags():
    assert "remote_access_request" in flags("Your computer is infected. Install remote access software for free repair.")
    assert "money_mule_request" in flags("A foreign officer needs your help moving money. Send your bank details.")
    assert "advance_fee_scam" in flags("A stranger offers to share an inheritance with you but asks for legal fees in advance.")
    assert "investment_claim" in flags("Guaranteed returns of 40% if you invest today")


def test_legitimate_counterexamples_have_no_flags():
    for message in [
        "Your exam form was submitted successfully.",
        "Our IT team can help with remote access after you open an approved support ticket.",
        "Your appointment is confirmed for Monday at 10 AM.",
        "Aapka mobile recharge successfully ho gaya hai.",
        "Please bring your documents to the meeting tomorrow.",
        "The bank branch will be closed tomorrow for a public holiday.",
    ]:
        assert flags(message) == [], message


def test_each_flag_has_a_reason_and_counts_match():
    result = check_message_rules("We are your bank. Share your OTP now or your account will be blocked.")
    assert len(result["flags"]) == len(result["reasons"]) == result["flag_count"]
    assert result["flags"] == list(dict.fromkeys(result["flags"]))  # no duplicates


def test_whitespace_and_case_are_normalized():
    assert "credential_request" in flags("PLEASE   SHARE\n\tYOUR   otp")


def test_pathological_input_is_fast():
    import time

    started = time.perf_counter()
    check_message_rules("pay " * 2500 + "fee " * 2500)
    check_message_rules("a" * 10000)
    assert time.perf_counter() - started < 2.0
