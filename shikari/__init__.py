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
