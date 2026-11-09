"""The legacy Splunk | search clause, as checked against Splunk 9.4 in the #41 spike."""

from shikari.build.queries import compile_search_clause, find_matching_field


def test_groups_are_ored_and_bracketed():
    # Splunk binds OR before the implicit AND: `a OR (b) c` would mean (a OR b) AND c
    clause = compile_search_clause({"process": ["whoami", "dscl . list"], "cmd": ["*user*", "*/server*"]})
    assert clause == ('process="whoami" OR (process="*dscl *" process="* . *" process="* list*") '
                      'OR cmd IN ("*user*", "*/server*")')


def test_contains_for_command_lines():
    clause = compile_search_clause({"process_command_line": ["whoami", "*$env:UserName*", "who"]}, contains=True)
    assert clause == 'process_command_line IN ("*whoami*", "*$env:UserName*", "*who*")'
    assert compile_search_clause({"process_name": ["whoami.exe"]}) == 'process_name="whoami.exe"'


def test_field_matching_ignores_prefix_and_separators():
    fields = ["_time", "device", "process_name", "process_command_line"]
    assert find_matching_field("properties.CommandLine", fields) == "process_command_line"
    assert find_matching_field("process_name", fields) == "process_name"
    assert find_matching_field("properties.RegistryKey", fields) is None
