import re
from collections.abc import Sequence
from typing import Dict, List

from app.detectors.url_utils import HOST_CHARS, host_allowed, url_host


class OutputDetector:
    """Detect data-exfiltration channels in LLM output.

    - markdown_image_exfil: a Markdown image pointing outside the allowlist.
      When the chat UI renders it, the browser fetches the URL by itself and
      sends whatever the injected instructions put in the query string.

    Enabled only for the llm_output context (rules.CONTEXT_RULES).
    """

    MARKDOWN_IMAGE = re.compile(rf"!\[[^\]]*\]\(\s*<?\s*https?://({HOST_CHARS})", re.IGNORECASE)

    def __init__(self, url_allowlist: Sequence[str] = ()) -> None:
        self.url_allowlist = tuple(url_allowlist)

    def detect(self, text: str) -> Dict[str, List[str]]:
        """
        Return: {"findings": ["markdown_image_exfil"], "exfil_hosts": ["evil.example"]}
        """
        hosts = [url_host(m.group(1)) for m in self.MARKDOWN_IMAGE.finditer(text)]
        bad_hosts = sorted({h for h in hosts if not host_allowed(h, self.url_allowlist)})
        return {"findings": ["markdown_image_exfil"] if bad_hosts else [], "exfil_hosts": bad_hosts}
