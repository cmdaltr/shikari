"""shikari console: the interactive console."""

import cmd
import os
import readline
import sys
from typing import Optional

from shikari.cli.banner import get_banner
from shikari.cli.modules import MODULE_REGISTRY
from shikari.cli.modules.base import BaseModule
from shikari.cli.search import run_search, SEARCH_DOMAINS


class ShikariConsole(cmd.Cmd):
    """Metasploit-style interactive console for Shikari."""

    intro = ""
    prompt = "\033[1;36mshikari\033[0m > "

    def __init__(self):
        super().__init__()
        self.current_module: Optional[BaseModule] = None
        self._setup_history()

    def _setup_history(self):
        """Configure readline history."""
        histfile = os.path.expanduser("~/.shikari_history")
        try:
            readline.read_history_file(histfile)
        except OSError:
            pass  # none yet, or unreadable: the console works without it
        import atexit

        def save():
            try:
                readline.write_history_file(histfile)
            except OSError:
                pass

        atexit.register(save)
        readline.set_history_length(1000)

    def preloop(self):
        print(get_banner())

    def postcmd(self, stop, line):
        if self.current_module:
            self.prompt = f"\033[1;36mshikari\033[0m (\033[1;33m{self.current_module.name}\033[0m) > "
        else:
            self.prompt = "\033[1;36mshikari\033[0m > "
        return stop

    # ------------------------------------------------------------------
    # Module selection
    # ------------------------------------------------------------------

    def do_use(self, arg):
        """Select a module: use <module_name>"""
        arg = arg.strip().lower()
        if arg not in MODULE_REGISTRY:
            print(f"  Unknown module: {arg}")
            print(f"  Available: {', '.join(sorted(MODULE_REGISTRY.keys()))}")
            return
        self.current_module = MODULE_REGISTRY[arg]()
        print(f"  Using module: {self.current_module.name}")

    def complete_use(self, text, line, begidx, endidx):
        return [m for m in MODULE_REGISTRY if m.startswith(text.lower())]

    # ------------------------------------------------------------------
    # Options
    # ------------------------------------------------------------------

    def do_set(self, arg):
        """Set a module option: set <OPTION> <value>"""
        if not self.current_module:
            print("  No module selected. Use 'use <module>' first.")
            return
        parts = arg.split(None, 1)
        if len(parts) < 2:
            print("  Usage: set <OPTION> <value>")
            return
        self.current_module.set_option(parts[0], parts[1])

    def complete_set(self, text, line, begidx, endidx):
        if not self.current_module:
            return []
        parts = line.split()
        if len(parts) <= 2:
            # Completing option name
            prefix = text.upper()
            return [o for o in self.current_module.get_option_names()
                    if o.startswith(prefix)]
        else:
            # Completing option value
            opt_name = parts[1].upper()
            opt = self.current_module.options.get(opt_name)
            if opt and opt.choices:
                return [c for c in opt.choices if c.lower().startswith(text.lower())]
        return []

    def do_unset(self, arg):
        """Clear a module option: unset <OPTION>"""
        if not self.current_module:
            print("  No module selected.")
            return
        self.current_module.unset_option(arg.strip())

    def complete_unset(self, text, line, begidx, endidx):
        if not self.current_module:
            return []
        return [o for o in self.current_module.get_option_names()
                if o.startswith(text.upper())]

    def do_show(self, arg):
        """Show information: show options | show modules"""
        arg = arg.strip().lower()
        if arg == "options":
            if self.current_module:
                self.current_module.show_options()
            else:
                print("  No module selected.")
        elif arg == "modules":
            print("\n  Available modules:\n")
            print(f"  {'Name':<18} Description")
            print(f"  {'----':<18} -----------")
            for name in sorted(MODULE_REGISTRY.keys()):
                inst = MODULE_REGISTRY[name]()
                print(f"  {name:<18} {inst.description}")
            print()
        else:
            print("  Usage: show options | show modules")

    def complete_show(self, text, line, begidx, endidx):
        opts = ["options", "modules"]
        return [o for o in opts if o.startswith(text.lower())]

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def do_run(self, arg):
        """Execute the selected module with current options."""
        self._execute_module()

    def do_execute(self, arg):
        """Execute the selected module (alias for run)."""
        self._execute_module()

    def _execute_module(self):
        if not self.current_module:
            print("  No module selected. Use 'use <module>' first.")
            return
        errors = self.current_module.validate()
        if errors:
            print("  Cannot run — missing required options:")
            for e in errors:
                print(f"    - {e}")
            return
        try:
            self.current_module.run()
        except KeyboardInterrupt:
            print("\n  Aborted.")
        except Exception as e:
            print(f"\n  Module error: {e}")
            import traceback
            traceback.print_exc()

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def do_back(self, arg):
        """Deselect the current module."""
        if self.current_module:
            print(f"  Left module: {self.current_module.name}")
        self.current_module = None

    def do_info(self, arg):
        """Show detailed module information."""
        if arg.strip():
            # info <module_name>
            name = arg.strip().lower()
            if name in MODULE_REGISTRY:
                MODULE_REGISTRY[name]().show_info()
            else:
                print(f"  Unknown module: {name}")
        elif self.current_module:
            self.current_module.show_info()
        else:
            print("  No module selected. Use 'info <module>' or select one with 'use'.")

    def complete_info(self, text, line, begidx, endidx):
        return [m for m in MODULE_REGISTRY if m.startswith(text.lower())]

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def do_search(self, arg):
        """Search across Shikari: search <domain> <term>
        Domains: bespoke | mitre | library | all
        Examples:
          search mitre PowerShell
          search library APT29
          search bespoke credential
          search all T1059"""
        parts = arg.strip().split(None, 1)
        if len(parts) == 0:
            print("  Usage: search <domain> <term>")
            print("  Domains: bespoke | mitre | library | all")
            return
        if len(parts) == 1:
            # Single arg — search all domains
            run_search(parts[0], "all")
        else:
            domain, term = parts
            if domain.lower() in list(SEARCH_DOMAINS.keys()) + ["all"]:
                run_search(term, domain.lower())
            else:
                # Treat entire arg as search term across all domains
                run_search(arg.strip(), "all")

    def complete_search(self, text, line, begidx, endidx):
        parts = line.split()
        if len(parts) <= 2:
            domains = list(SEARCH_DOMAINS.keys()) + ["all"]
            return [d for d in domains if d.startswith(text.lower())]
        return []

    # ------------------------------------------------------------------
    # Exit
    # ------------------------------------------------------------------

    def do_exit(self, arg):
        """Exit the console."""
        print("  Exiting the console...")
        return True

    def do_quit(self, arg):
        """Exit the console."""
        return self.do_exit(arg)

    def do_EOF(self, arg):
        """Handle Ctrl+D."""
        print()
        return self.do_exit(arg)

    # ------------------------------------------------------------------
    # Help
    # ------------------------------------------------------------------

    def do_help(self, arg):
        """Show help for commands."""
        if arg:
            super().do_help(arg)
            return
        print("\n  Core Commands")
        print("  =============\n")
        print(f"  {'Command':<15} Description")
        print(f"  {'-------':<15} -----------")
        commands = [
            ("use", "Select a module (e.g., use generate)"),
            ("back", "Deselect the current module"),
            ("show", "Show options or modules (e.g., show options)"),
            ("set", "Set a module option (e.g., set GROUP APT29)"),
            ("unset", "Clear a module option"),
            ("run", "Execute the selected module"),
            ("search", "Search bespoke | mitre | library | all (e.g., search mitre PowerShell)"),
            ("info", "Show module information"),
            ("help", "Show this help"),
            ("exit", "Exit the console"),
        ]
        for name, desc in commands:
            print(f"  {name:<15} {desc}")
        print()

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def emptyline(self):
        """Do nothing on empty line (don't repeat last command)."""
        pass

    def default(self, line):
        """Handle unknown commands."""
        print(f"  Unknown command: {line}. Type 'help' for available commands.")


def main():
    """Entry point for shikari console."""
    console = ShikariConsole()
    try:
        console.cmdloop()
    except KeyboardInterrupt:
        print("\n  Exiting the console...")


if __name__ == "__main__":
    main()
