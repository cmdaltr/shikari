"""ASCII banner for archer-cli console."""

from archer.cli import __version__


def get_banner() -> str:
    from archer.cli.modules import MODULE_REGISTRY

    module_count = len(MODULE_REGISTRY)
    return f"""
\033[36m
   █████╗ ██████╗  ██████╗██╗  ██╗███████╗██████╗
  ██╔══██╗██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗
  ███████║██████╔╝██║     ███████║█████╗  ██████╔╝
  ██╔══██║██╔══██╗██║     ██╔══██║██╔══╝  ██╔══██╗
  ██║  ██║██║  ██║╚██████╗██║  ██║███████╗██║  ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
\033[0m\033[1m  archer-cli console\033[0m
  \033[90m{module_count} modules | v{__version__}\033[0m
  \033[90mType 'help' for commands, 'show modules' to list modules\033[0m
"""
