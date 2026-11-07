from aegis.generalization.ladders import PseudonymRegistry, coarse_value, render
from aegis.models import Finding, Severity


def F(t, text, v):
    return Finding(id="p1", type=t, category="quasi_identifier", start=0, end=len(text), text=text, confidence=0.9,
                   severity=Severity.LOW, detector="x", evidence="x", value_norm=v)


def test_ladders_render_and_coarse_values():
    reg = PseudonymRegistry()
    assert render(F("age", "34", "34"), "band_5", reg, "h") == "30–34"
    assert coarse_value("age", "34", "band_5") == "30-34"
    assert render(F("city", "Jeddah", "jeddah"), "region", reg, "h") == "the Western Region"
    assert render(F("city", "بالرياض", "riyadh"), "region", reg, "h") == "بالمنطقة الوسطى"
    assert render(F("money_amount", "SAR 28,500", "28500"), "range", reg, "h") == "SAR 25K–50K"
    assert render(F("person_name", "Sara Ali", "sara ali"), "pseudonym", reg, "k1") == "[PERSON_1]"
    assert render(F("person_name", "Sara Ali", "sara ali"), "pseudonym", reg, "k1") == "[PERSON_1]"  # consistent


def test_unknown_value_never_leaks():
    reg = PseudonymRegistry()
    out = render(F("city", "Atlantis", "atlantis"), "region", reg, "h")
    assert "Atlantis" not in out


def test_same_request_three_policies_three_decisions(aegis):
    p = "Draft a reply to Mr. Fahad Alotaibi about his salary of SAR 31,000 being paid late. This is confidential."
    r = aegis.simulate(p, purpose="hr_case_summary")
    assert r["actions"]["strict"] == "BLOCK"
    assert r["actions"]["balanced"] in ("WARN", "GENERALIZE")
    assert r["actions"]["permissive"] in ("ALLOW", "WARN")
    assert not r["same_decision"]


def test_purpose_changes_what_is_kept(aegis):
    csv = "name,age,city,complaint\nNoura Alqahtani,27,Riyadh,Late delivery\n"
    demo = aegis.evaluate("Average age by region please", content=csv, purpose="demographic_analysis", dry_run=True)
    supp = aegis.evaluate("Summarize the complaint themes", content=csv, purpose="support_summary", dry_run=True)
    assert "25–29" in demo.minimized_content and "Noura" not in demo.minimized_content
    assert "[AGE]" in supp.minimized_content and "27" not in supp.minimized_content


def test_decisions_are_deterministic(aegis):
    p = "Summarize: Sara Ali, 41, Jeddah, SAR 12,000 invoice, project Falcon."
    a = aegis.evaluate(p, dry_run=True)
    b = aegis.evaluate(p, dry_run=True)
    assert a.action == b.action and a.minimized_prompt == b.minimized_prompt and [r.rule_id for r in a.fired_rules] == [r.rule_id for r in b.fired_rules]


def test_credential_block_and_counterfactual(aegis):
    d = aegis.evaluate("why 401? token sk-proj-Q7f9Lk2mN4pR8sT1vW3xY6zA0bC5dE", purpose="code_review")
    assert d.action.value == "BLOCK" and d.minimized_prompt is None
    assert d.counterfactual["steps"] and d.counterfactual["target_action"] in ("ALLOW", "WARN", "GENERALIZE")


def test_unknown_purpose_or_policy_rejected(aegis):
    import pytest
    from aegis.gateway import InputError
    with pytest.raises(InputError):
        aegis.evaluate("hello", purpose="nope")
    with pytest.raises(InputError):
        aegis.evaluate("hello", policy="nope")
