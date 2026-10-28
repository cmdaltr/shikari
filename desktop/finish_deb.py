"""
Add Archer's AppArmor profile to the .deb Briefcase built.

Ubuntu 24.04 and later stop unconfined programs creating user namespaces, which WebKitGTK's sandbox
needs: without a profile that allows them the window never opens. The profile goes in only where
that restriction exists, so a Debian whose AppArmor doesn't know the rule is left alone. Briefcase
rewrites the package's DEBIAN folder as it packages, so this runs on the finished .deb:

    python desktop/finish_deb.py dist/archer_*.deb
"""
import subprocess
import sys
import tempfile
from pathlib import Path

PROFILE = """\
# Lets Archer's web view (WebKitGTK) sandbox itself where unprivileged user namespaces are restricted
abi <abi/4.0>,
include <tunables/global>

profile archer /usr/bin/archer flags=(unconfined) {
  userns,

  include if exists <local/archer>
}
"""

POSTINST = """\
#!/bin/sh
set -e
if [ "$1" = configure ] && [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
    cp /usr/lib/archer/apparmor/archer /etc/apparmor.d/archer
    if command -v apparmor_parser >/dev/null && [ -d /sys/kernel/security/apparmor ]; then
        apparmor_parser -r -T -W /etc/apparmor.d/archer || true
    fi
fi
"""

PRERM = """\
#!/bin/sh
set -e
if [ -e /etc/apparmor.d/archer ]; then
    if command -v apparmor_parser >/dev/null && [ -d /sys/kernel/security/apparmor ]; then
        apparmor_parser -R /etc/apparmor.d/archer || true
    fi
    rm -f /etc/apparmor.d/archer
fi
"""


def finish(deb: Path):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "root"
        subprocess.run(["dpkg-deb", "-R", str(deb), str(root)], check=True)
        profile = root / "usr" / "lib" / "archer" / "apparmor" / "archer"
        profile.parent.mkdir(parents=True, exist_ok=True)
        profile.write_text(PROFILE)
        profile.chmod(0o644)
        for name, text in (("postinst", POSTINST), ("prerm", PRERM)):
            script = root / "DEBIAN" / name
            script.write_text(text)
            script.chmod(0o755)
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(root), str(deb)], check=True)
    print(f"Added the AppArmor profile to {deb.name}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for arg in sys.argv[1:]:
        finish(Path(arg))
