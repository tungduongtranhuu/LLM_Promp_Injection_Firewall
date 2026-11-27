import re
from collections.abc import Sequence
from typing import Dict, List

from app.detectors.secret_patterns import credential_disclosures, known_secret_kinds
from app.detectors.url_utils import HOST_CHARS, host_allowed, url_host


class OutputDetector:
    """Detect data leaks and exfiltration channels in LLM output (OWASP LLM02).

    - markdown_image_exfil: a Markdown image pointing outside the allowlist.
      When the chat UI renders it, the browser fetches the URL by itself and
      sends whatever the injected instructions put in the query string.
    - secret_known_format: a credential in a well-known format (Stripe, AWS,
      GitHub, Slack, Google API key, private key, JWT).
    - credential_disclosure: a password-like value given after a credential
      keyword ("le mot de passe est ...", "password: ...").

    Enabled only for the llm_output context (rules.CONTEXT_RULES).
    The secret values themselves are never returned, only their kind.
    """

    TECHNIQUES = ("markdown_image_exfil", "secret_known_format", "credential_disclosure")

    MARKDOWN_IMAGE = re.compile(rf"!\[[^\]]*\]\(\s*<?\s*https?://({HOST_CHARS})", re.IGNORECASE)

    def __init__(self, url_allowlist: Sequence[str] = ()) -> None:
        self.url_allowlist = tuple(url_allowlist)

    def detect(self, text: str) -> Dict[str, List[str]]:
        """
        Return: {"findings": ["markdown_image_exfil", "secret_known_format"],
                 "exfil_hosts": ["evil.example"], "secret_kinds": ["aws_access_key_id"]}
        """
        hosts = [url_host(m.group(1)) for m in self.MARKDOWN_IMAGE.finditer(text)]
        bad_hosts = sorted({h for h in hosts if not host_allowed(h, self.url_allowlist)})
        secret_kinds = known_secret_kinds(text)

        findings = []
        if bad_hosts:
            findings.append("markdown_image_exfil")
        if secret_kinds:
            findings.append("secret_known_format")
        if credential_disclosures(text):
            findings.append("credential_disclosure")
        return {"findings": findings, "exfil_hosts": bad_hosts, "secret_kinds": secret_kinds}
