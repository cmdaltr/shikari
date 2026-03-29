"""Module registry for the ADF console."""

from .generate import GenerateModule
from .correlate import CorrelateModule
from .hunt import HuntModule
from .emulate import EmulateModule

MODULE_REGISTRY = {
    "generate": GenerateModule,
    "correlate": CorrelateModule,
    "hunt": HuntModule,
    "emulate": EmulateModule,
}
