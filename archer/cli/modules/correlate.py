"""Build correlation queries from existing detection YAML files."""

from .base import BaseModule, ModuleOption


class CorrelateModule(BaseModule):
    name = "correlate"
    description = "Correlate generated detections into multi-query searches"
    author = "Archer Team"

    def _register_options(self):
        self.options = {
            "MIN_RELEVANCE": ModuleOption(
                name="MIN_RELEVANCE",
                description="Minimum relevance score for a correlation, 0-1 (blank = configured)",
            ),
            "GROUP": ModuleOption(
                name="GROUP",
                description="Threat group to correlate",
                required=True,
            ),
            "YAML_DIR": ModuleOption(
                name="YAML_DIR",
                description="Directory containing YAML files",
                default="data/groups",
            ),
            "OUTPUT": ModuleOption(
                name="OUTPUT",
                description="Output JSON file path",
            ),
            "MIN_QUERIES": ModuleOption(
                name="MIN_QUERIES",
                description="Minimum queries per correlation",
                default=2,
            ),
            "MAX_QUERIES": ModuleOption(
                name="MAX_QUERIES",
                description="Maximum queries per correlation",
                default=5,
            ),
            "VERBOSE": ModuleOption(
                name="VERBOSE",
                description="Enable verbose output",
                default=False,
            ),
        }

    def run(self):
        from archer.ai.genai import build_correlation_queries

        group = self.options["GROUP"].effective_value
        print(f"\n[*] Building correlations for {group}\n")

        import os

        # The engine reads the threshold from the environment on each run
        if self.options["MIN_RELEVANCE"].effective_value:
            os.environ["CORRELATION_MIN_RELEVANCE"] = str(float(self.options["MIN_RELEVANCE"].effective_value))
        build_correlation_queries(
            yaml_dir=self.options["YAML_DIR"].effective_value,
            output_file=self.options["OUTPUT"].effective_value,
            min_queries=int(self.options["MIN_QUERIES"].effective_value),
            max_queries=int(self.options["MAX_QUERIES"].effective_value),
            threat_group=group,
            verbose=bool(self.options["VERBOSE"].effective_value),
        )
