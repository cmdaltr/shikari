"""Base module class for shikari-cli console."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ModuleOption:
    """A single configurable option for a module."""

    name: str
    description: str
    required: bool = False
    default: Any = None
    current_value: Any = None
    choices: Optional[List[str]] = None

    @property
    def display_value(self) -> str:
        if self.current_value is not None:
            return str(self.current_value)
        if self.default is not None:
            return str(self.default)
        return ""

    @property
    def effective_value(self) -> Any:
        return self.current_value if self.current_value is not None else self.default


class BaseModule(ABC):
    """Abstract base class for all ADF modules."""

    name: str = ""
    description: str = ""
    author: str = ""
    references: List[str] = []

    def __init__(self):
        self.options: Dict[str, ModuleOption] = {}
        self._register_options()

    @abstractmethod
    def _register_options(self) -> None:
        """Register this module's options."""
        ...

    @abstractmethod
    def run(self) -> None:
        """Execute the module with current options."""
        ...

    def validate(self) -> List[str]:
        """Return list of validation errors. Empty list means valid."""
        errors = []
        for name, opt in self.options.items():
            if opt.required and opt.effective_value is None:
                errors.append(f"Required option {name} is not set")
        return errors

    def show_options(self) -> None:
        """Print the options table."""
        print(f"\n  Module options ({self.name}):\n")
        print(f"  {'Name':<20} {'Current Value':<25} {'Required':<10} Description")
        print(f"  {'----':<20} {'-------------':<25} {'--------':<10} -----------")
        for name, opt in self.options.items():
            req = "yes" if opt.required else "no"
            val = opt.display_value
            print(f"  {name:<20} {val:<25} {req:<10} {opt.description}")
        print()

    def show_info(self) -> None:
        """Print module description."""
        print(f"\n  Name:        {self.name}")
        print(f"  Description: {self.description}")
        print(f"  Author:      {self.author}")
        if self.references:
            print(f"  References:")
            for ref in self.references:
                print(f"    - {ref}")
        print()

    def get_option_names(self) -> List[str]:
        """Return all option names for tab-completion."""
        return list(self.options.keys())

    def set_option(self, name: str, value: str) -> bool:
        """Set an option value. Returns True on success."""
        upper_name = name.upper()
        if upper_name not in self.options:
            print(f"  Unknown option: {name}")
            return False
        opt = self.options[upper_name]
        # Boolean coercion
        if isinstance(opt.default, bool):
            value = value.lower() in ("true", "yes", "1", "on")
        # Integer coercion
        elif isinstance(opt.default, int) and opt.default is not None:
            try:
                value = int(value)
            except ValueError:
                print(f"  {upper_name} requires an integer value")
                return False
        # Validate choices
        if opt.choices and str(value).lower() not in [c.lower() for c in opt.choices]:
            print(f"  Invalid value for {upper_name}. Choose from: {', '.join(opt.choices)}")
            return False
        opt.current_value = value
        print(f"  {upper_name} => {value}")
        return True

    def unset_option(self, name: str) -> bool:
        """Clear an option value. Returns True on success."""
        upper_name = name.upper()
        if upper_name not in self.options:
            print(f"  Unknown option: {name}")
            return False
        self.options[upper_name].current_value = None
        print(f"  Unset {upper_name}")
        return True
