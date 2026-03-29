# Task: Create an Interactive Console for an Existing CLI Binary

You are wrapping an existing command-line tool into a Metasploit-style interactive console
using Python's built-in `cmd.Cmd` module. The console should feel like msfconsole — module
selection, option setting, tab-completion, and execution.

## Input

The existing CLI binary is: `<BINARY_NAME>`
Located at: `<BINARY_PATH>`

Read the binary's source code and extract:
1. All subcommands (these become **modules**)
2. All flags/arguments per subcommand (these become **options**)
3. Which options are required vs optional, their defaults, and any constrained choices
4. The underlying function each subcommand calls (the console delegates to these directly)

## Output Structure

Create the following files:

```
<project>/
  <console_name>                    # Executable entry point (chmod +x, #!/usr/bin/env python3)
  <package>/cli/
    __init__.py                     # Package init with __version__
    banner.py                       # ASCII art banner with version + module count
    console.py                      # Main Console(cmd.Cmd) class
    search.py                       # Optional: search functionality across project data
    modules/
      __init__.py                   # MODULE_REGISTRY dict mapping name -> class
      base.py                       # BaseModule ABC + ModuleOption dataclass
      <module_1>.py                 # One file per subcommand
      <module_2>.py
      ...
```

## BaseModule Design

```python
@dataclass
class ModuleOption:
    name: str                           # Display name (UPPER_CASE)
    description: str                    # One-line help text
    required: bool = False              # Must be set before run()
    default: Any = None                 # Default value (also determines type coercion)
    current_value: Any = None           # User-set value (None = use default)
    choices: Optional[List[str]] = None # Constrained values (enables tab-completion)

    @property
    def effective_value(self) -> Any:
        return self.current_value if self.current_value is not None else self.default

class BaseModule(ABC):
    name: str           # Module name (lowercase, matches subcommand)
    description: str    # One-line description shown in `show modules`

    def _register_options(self) -> None: ...   # Populate self.options dict
    def run(self) -> None: ...                 # Execute -- delegates to existing function
    def validate(self) -> List[str]: ...       # Return errors for missing required options
    def show_options(self) -> None: ...        # Print formatted options table
    def set_option(name, value) -> bool: ...   # Set with type coercion + choice validation
```

## Module Implementation Rules

For each subcommand in the original CLI:

1. Create a module class inheriting BaseModule
2. Map each CLI flag to a ModuleOption:
   - `--flag` with `action="store_true"` -> `ModuleOption(default=False)` (bool coercion)
   - `--flag VALUE` -> `ModuleOption(default=None)` or with a default
   - `--flag {a,b,c}` (choices) -> `ModuleOption(choices=["a","b","c"])`
   - Positional required arg -> `ModuleOption(required=True)`
3. The `run()` method must:
   - Use **lazy imports** (import inside run, not at module level) to keep startup fast
   - Call the **existing underlying function** directly -- do NOT reimplement logic
   - Print a status line before delegating: `[*] Running <module> with <key option>...`

## Console Commands (implement all of these)

| Command | Description |
|---------|-------------|
| `use <module>` | Select a module. Prompt changes to `console (module) >` |
| `back` | Deselect current module. Prompt reverts. |
| `show modules` | List all modules with descriptions |
| `show options` | Print current module's options table (Name, Current Value, Required, Description) |
| `set <OPT> <val>` | Set option. Auto-coerce bool/int based on default type. Validate choices. |
| `unset <OPT>` | Clear option back to default |
| `run` / `execute` | Validate required options, then call module.run(). Catch KeyboardInterrupt. |
| `info [module]` | Show module name, description, author, references |
| `search <term>` | Optional: search across project data |
| `help` | Print formatted command table (not the default cmd.Cmd help) |
| `exit` / `quit` / Ctrl+D | Exit cleanly |

## Tab-Completion Rules

Implement `complete_<cmd>` methods for:
- `use` -> complete module names
- `set` -> first arg completes option names (UPPER_CASE), second arg completes choices if available
- `unset` -> complete option names
- `show` -> complete "options", "modules"
- `info` -> complete module names
- `search` -> complete search domain names (if search is implemented)

## Console Behaviour

- Prompt: `<console_name> >` when no module selected, `<console_name> (<module>) >` when selected
- Use ANSI colour codes in the prompt (cyan for console name, yellow for module name)
- Empty line does nothing (override `emptyline()`)
- Unknown commands print "Unknown command: X. Type 'help' for available commands."
- Persist command history to `~/.<console_name>_history` via readline
- Print an ASCII banner on startup via `preloop()`
- Wrap `run()` execution in try/except for KeyboardInterrupt and general Exception

## Banner

Create a distinctive ASCII art banner that includes:
- Project name / console name
- Module count (read from MODULE_REGISTRY)
- Version number
- "Type 'help' for commands" hint

## Entry Point

The executable script at project root:
```python
#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from <package>.cli.console import main

if __name__ == "__main__":
    main()
```

The `main()` function in console.py:
```python
def main():
    console = Console()
    try:
        console.cmdloop()
    except KeyboardInterrupt:
        print("\nExiting...")
```

## What NOT to Do

- Do NOT add external dependencies -- use only stdlib (cmd, readline, dataclasses, pathlib, os)
- Do NOT reimplement business logic -- always delegate to existing functions
- Do NOT use `input()` for option setting -- everything goes through `set`/`show options`/`run`
- Do NOT create a flat script -- use the module architecture above
- Do NOT skip tab-completion -- it is the core UX differentiator from a plain CLI
