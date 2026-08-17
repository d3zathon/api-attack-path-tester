from .bfla import BflaCheck
from .bola import BolaCheck
from .business_logic import BusinessLogicCheck
from .param_tampering import ParamTamperingCheck
from .privesc import PrivEscCheck

ALL_CHECKS = {
    "bola": BolaCheck,
    "bfla": BflaCheck,
    "privesc": PrivEscCheck,
    "param_tampering": ParamTamperingCheck,
    "business_logic": BusinessLogicCheck,
}

__all__ = [
    "BolaCheck", "BflaCheck", "PrivEscCheck", "ParamTamperingCheck",
    "BusinessLogicCheck", "ALL_CHECKS",
]
