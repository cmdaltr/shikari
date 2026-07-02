"""Module registry for the ADF console."""

from .generate import GenerateModule
from .correlate import CorrelateModule
from .hunt import HuntModule
from archer.config import EMULATION_ENABLED

MODULE_REGISTRY = {
    "generate": GenerateModule,
    "correlate": CorrelateModule,
    "hunt": HuntModule,
}

if EMULATION_ENABLED:
    from .emulate import EmulateModule
    MODULE_REGISTRY["emulate"] = EmulateModule
