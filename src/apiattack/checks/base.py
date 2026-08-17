from __future__ import annotations

import abc
from typing import List

from ..config.loader import ScanConfig
from ..engine.http_client import HttpClient
from ..models import Endpoint, Finding


class BaseCheck(abc.ABC):
    """A check module inspects endpoints under a given config and role set, and returns
    *candidate* findings. Candidates are unconfirmed until the verification layer confirms
    them - checks should err toward flagging plausible issues, verification narrows them down.
    """

    name: str = "base"
    vuln_class: str = ""

    def __init__(self, config: ScanConfig, client: HttpClient):
        self.config = config
        self.client = client

    @abc.abstractmethod
    def run(self, endpoints: List[Endpoint]) -> List[Finding]:
        ...

    def fill_path(self, path: str, values: dict) -> str:
        out = path
        for k, v in values.items():
            out = out.replace("{" + k + "}", str(v))
        return out
