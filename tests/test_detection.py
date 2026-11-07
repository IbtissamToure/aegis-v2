from aegis.detection.detector import Detector
from aegis.detection.validators import iban_valid, luhn_valid, saudi_id_valid
from tests.conftest import make_id

D = Detector(codenames={"falcon": "falcon", "الصقر": "falcon"})


def types(text):
    return {f.type for f in D.detect(text) if f.confidence >= 0.5}


def test_validators():
    assert saudi_id_valid(make_id("103456789"))
    assert not saudi_id_valid("1034567890")
    assert iban_valid("SA03 8000 0000 6080 1016 7519")
    assert not iban_valid("SA03 8000 0000 6080 1016 7518")
    assert luhn_valid("4111 1111 1111 1111") and not luhn_valid("4111 1111 1111 1112")


def test_saudi_id_requires_checksum_or_context():
    nid = make_id("112233445")
    assert "national_id" in types(f"record {nid}")
    bad = nid[:-1] + str((int(nid[-1]) + 1) % 10)
    assert "national_id" not in types(f"order {bad} shipped")  # random 10-digit number, no context
    assert "national_id" in types(f"ID number {bad}")  # context keeps it, at lower confidence


def test_english_pii_and_quasi_identifiers():
    t = types("Mr. Fahad Alotaibi, 34 years old, senior manager in the Finance department in Jeddah, email fahad@corp.sa, 0551234567")
    assert {"person_name", "age", "job_title", "department", "city", "email", "phone"} <= t


def test_arabic_detection_with_clitics():
    found = {f.type: f for f in D.detect("الموظفة نورة العتيبي عمرها 29 سنة وتعمل مهندسة في الموارد البشرية بالرياض")}
    assert found["person_name"].text == "نورة العتيبي"
    assert found["age"].value_norm == "29"
    assert found["city"].value_norm == "riyadh"
    assert found["department"].value_norm == "hr"


def test_credentials():
    t = types("key sk-proj-Q7f9Lk2mN4pR8sT1vW3xY6zA0bC5dE password: Winter2026! postgres://u:p4ss@db.corp.internal/x AKIAABCDEFGHIJKLMNOP")
    assert {"api_key", "password", "connection_string"} <= t


def test_tabular_headers_type_cells():
    fs = D.detect("name,age,city\nSara Ali,41,Jeddah\n")
    by = {f.type: f.text for f in fs}
    assert by["age"] == "41" and by["person_name"] == "Sara Ali" and by["city"] == "Jeddah"


def test_project_registry_en_ar():
    assert "project_codename" in types("Status of Project Falcon?")
    fs = [f for f in D.detect("ما هي حالة مشروع الصقر؟") if f.type == "project_codename"]
    assert fs and fs[0].value_norm == "falcon"


def test_benign_text_has_no_strong_findings():
    benign = ["Write a poem about the sea.", "Explain how photosynthesis works in simple terms.", "اكتب لي خطة مذاكرة لمادة الرياضيات",
              "What is 2+2?", "Translate 'good morning' to French."]
    for b in benign:
        strong = [f for f in D.detect(b) if f.confidence >= 0.5 and f.category in ("pii", "credential", "financial")]
        assert not strong, (b, strong)


def test_offsets_point_to_original_text_with_diacritics():
    text = "الموظفُ أحمد بن خالدٍ"
    for f in D.detect(text):
        assert text[f.start:f.end] == f.text
