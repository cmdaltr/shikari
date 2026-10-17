# Loaded on first use, so importing a light module (archer.service, which stops and checks a
# broken app) doesn't load the whole pipeline
_EXPORTS = {
    "compile_query": "archer.build.detections",
    "construct_yaml": "archer.build.yaml",
    "get_stix_data": "archer.mitre.enterprise",
    "obtain_all_techniques": "archer.mitre.enterprise",
    "obtain_technique_descriptions": "archer.mitre.enterprise",
    "check_group_in_mitre": "archer.mitre.enterprise",
    "retrieve_group": "archer.mitre.retrieve",
    "retrieve_techniques": "archer.mitre.retrieve",
    "retrieve_procedures": "archer.mitre.retrieve",
}

__all__ = list(_EXPORTS)


def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(f"module 'archer' has no attribute {name!r}")
    import importlib
    value = getattr(importlib.import_module(_EXPORTS[name]), name)
    globals()[name] = value
    return value
