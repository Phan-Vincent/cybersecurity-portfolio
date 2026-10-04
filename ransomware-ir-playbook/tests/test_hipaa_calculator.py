"""Breach-notification deadline math (45 CFR 164.400-414)."""

import pytest

import hipaa_notification_calculator as calc


def deadlines(count, state="CA", date="2026-06-15", breach_type="unauthorized_access"):
    return calc.calculate_hipaa_deadlines(date, count, state, breach_type)["deadlines"]


def test_individual_notice_is_60_days():
    assert deadlines(10)["individual_notice"]["deadline"] == "2026-08-14"


@pytest.mark.parametrize("count, immediate", [(499, False), (500, True), (501, True)])
def test_hhs_threshold_is_500_or_more(count, immediate):
    # 164.408(b): "500 or more individuals" -> notify HHS within 60 days
    hhs = deadlines(count)["hhs_secretary_notice"]
    assert hhs["immediate"] is immediate
    assert hhs["deadline"] == ("2026-08-14" if immediate else "2027-03-01")


@pytest.mark.parametrize("count, required", [(499, False), (500, False), (501, True)])
def test_media_threshold_is_more_than_500(count, required):
    # 164.406(a): "more than 500 residents of a State or jurisdiction"
    assert deadlines(count)["media_notice"]["required"] is required


def test_small_breach_annual_log_handles_leap_year():
    # Discovered in 2027 -> due 60 days after Dec 31 2027 -> Feb 29 2028
    hhs = deadlines(10, date="2027-03-10")["hhs_secretary_notice"]
    assert hhs["deadline"] == "2028-02-29"


def test_checklist_hhs_item_matches_deadline():
    for count in (499, 500):
        schedule = calc.calculate_hipaa_deadlines("2026-06-15", count, "CA")
        item = next(i for i in schedule["checklist_items"] if i["category"] == "hhs_notification")
        assert item["deadline"] == schedule["deadlines"]["hhs_secretary_notice"]["deadline"]
        assert item["urgent"] is (count >= 500)


def test_state_board_hours_and_additional_deadline():
    d = deadlines(1200, state="fl")
    assert d["state_pharmacy_board_notice"]["hours_from_discovery"] == 72
    assert d["additional_state_notices"][0]["days_from_discovery"] == 30


def test_unknown_state_uses_default():
    s = calc.calculate_hipaa_deadlines("2026-06-15", 10, "ZZ")
    assert s["state_info"]["name"] == "Unknown / Other"


def test_ransomware_adds_guidance():
    s = calc.calculate_hipaa_deadlines("2026-06-15", 10, "CA", "ransomware")
    assert any("presumed" in n for n in s["ransomware_specific_notes"])


def test_iso_datetime_accepted_and_garbage_rejected():
    assert calc.calculate_hipaa_deadlines("2026-06-15T09:30:00", 1, "CA")["metadata"]["discovery_date"] == "2026-06-15"
    with pytest.raises(ValueError):
        calc.calculate_hipaa_deadlines("06/15/2026", 1, "CA")


@pytest.mark.parametrize("state, count, expected_days", [
    ("TX", 249, None), ("TX", 250, 30),   # 521.053(i) as amended by SB 768 (2023)
    ("FL", 499, None), ("FL", 500, 30),   # 501.171(3): 500 or more residents
])
def test_state_ag_notice_thresholds(state, count, expected_days):
    notices = deadlines(count, state=state)["additional_state_notices"]
    if expected_days is None:
        assert notices == []
    else:
        assert notices[0]["days_from_discovery"] == expected_days
        assert notices[0]["deadline"] == "2026-07-15"
