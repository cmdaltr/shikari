# Load a repo/CWD .env (if present) before any submodule reads os.getenv() at import time
# (e.g. shikari.auth.email's SMTP_* constants). python-dotenv is a dependency; a no-op when
# no .env exists. override=False, so an explicit shell export always wins over the file.
try:
    from dotenv import find_dotenv as _find_dotenv, load_dotenv as _load_dotenv

    # usecwd=True searches up from the working directory (where a deployer keeps .env and
    # runs shikari), not the installed package dir, so it works for a site-packages install.
    _load_dotenv(_find_dotenv(usecwd=True))
except Exception:
    pass

# Loaded on first use, so importing a light module (shikari.service, which stops and checks a
# broken app) doesn't load the whole pipeline
_EXPORTS = {
    "compile_query": "shikari.build.detections",
    "construct_yaml": "shikari.build.yaml",
    "get_stix_data": "shikari.mitre.enterprise",
    "obtain_all_techniques": "shikari.mitre.enterprise",
    "obtain_technique_descriptions": "shikari.mitre.enterprise",
    "check_group_in_mitre": "shikari.mitre.enterprise",
    "retrieve_group": "shikari.mitre.retrieve",
    "retrieve_techniques": "shikari.mitre.retrieve",
    "retrieve_procedures": "shikari.mitre.retrieve",
}

__all__ = list(_EXPORTS)


def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(f"module 'shikari' has no attribute {name!r}")
    import importlib
    value = getattr(importlib.import_module(_EXPORTS[name]), name)
    globals()[name] = value
    return value
