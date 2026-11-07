"""Registry of entity types Aegis understands.

Adding a new type: add an entry here, a recognizer in ``recognizers.py`` (or a
lexicon), and optionally a generalization ladder in
``aegis/generalization/ladders.py``. Nothing else needs to change.
"""
from aegis.models import Severity

# category: pii | credential | financial | confidential | quasi_identifier
ENTITY_TYPES: dict[str, dict] = {
    # Direct identifiers
    "person_name": {"category": "pii", "severity": Severity.HIGH, "label": "Person name"},
    "email": {"category": "pii", "severity": Severity.MEDIUM, "label": "Email address"},
    "phone": {"category": "pii", "severity": Severity.MEDIUM, "label": "Phone number"},
    "national_id": {"category": "pii", "severity": Severity.CRITICAL, "label": "National ID / Iqama"},
    "passport": {"category": "pii", "severity": Severity.CRITICAL, "label": "Passport number"},
    "date_of_birth": {"category": "pii", "severity": Severity.HIGH, "label": "Date of birth"},
    "address": {"category": "pii", "severity": Severity.HIGH, "label": "Street address"},
    # Financial
    "iban": {"category": "financial", "severity": Severity.CRITICAL, "label": "IBAN"},
    "payment_card": {"category": "financial", "severity": Severity.CRITICAL, "label": "Payment card"},
    "money_amount": {"category": "financial", "severity": Severity.LOW, "label": "Money amount"},
    "salary": {"category": "financial", "severity": Severity.HIGH, "label": "Salary / compensation"},
    # Credentials
    "api_key": {"category": "credential", "severity": Severity.CRITICAL, "label": "API key / token"},
    "password": {"category": "credential", "severity": Severity.CRITICAL, "label": "Password"},
    "private_key": {"category": "credential", "severity": Severity.CRITICAL, "label": "Private key"},
    "connection_string": {"category": "credential", "severity": Severity.CRITICAL, "label": "Connection string"},
    # Confidential business information
    "confidential_marker": {"category": "confidential", "severity": Severity.HIGH, "label": "Confidentiality marker"},
    "business_sensitive": {"category": "confidential", "severity": Severity.MEDIUM, "label": "Business-sensitive topic"},
    "project_codename": {"category": "confidential", "severity": Severity.MEDIUM, "label": "Internal project"},
    "internal_host": {"category": "confidential", "severity": Severity.MEDIUM, "label": "Internal host / IP"},
    # Quasi-identifiers (harmless alone, identifying in combination)
    "age": {"category": "quasi_identifier", "severity": Severity.LOW, "label": "Age"},
    "city": {"category": "quasi_identifier", "severity": Severity.LOW, "label": "City / office"},
    "department": {"category": "quasi_identifier", "severity": Severity.LOW, "label": "Department"},
    "job_title": {"category": "quasi_identifier", "severity": Severity.LOW, "label": "Job title"},
    "nationality": {"category": "quasi_identifier", "severity": Severity.LOW, "label": "Nationality"},
    "gender": {"category": "quasi_identifier", "severity": Severity.LOW, "label": "Gender"},
    "join_year": {"category": "quasi_identifier", "severity": Severity.LOW, "label": "Joining year"},
    "date": {"category": "quasi_identifier", "severity": Severity.LOW, "label": "Date"},
}

# Quasi-identifier types whose values are tracked by the identifiability ledger.
# project_codename is confidential AND identifying (small teams), so it is tracked too.
TRACKED_ATTRIBUTES = {
    "age": "age",
    "city": "city",
    "department": "department",
    "job_title": "job_title",
    "nationality": "nationality",
    "gender": "gender",
    "join_year": "join_year",
    "project_codename": "project",
}


def category_of(entity_type: str) -> str:
    return ENTITY_TYPES[entity_type]["category"]


def severity_of(entity_type: str) -> Severity:
    return ENTITY_TYPES[entity_type]["severity"]
