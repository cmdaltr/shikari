"""
Docker SIEM Manager

Manages SIEM containers for detection validation.
Supports Splunk, Elastic, Google SecOps (simulator), and MDE (simulator).

Can use either:
1. Pre-started containers via docker-compose profiles (preferred)
2. Ephemeral containers spawned on-demand (fallback)
"""

import os
import time
import uuid
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import json
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


# Docker-compose container names and their configurations
COMPOSE_CONTAINERS = {
    "splunk": {
        "container_name": "shikari-splunk",
        "ports": {"web": 8001, "api": 8089, "hec": 8088},
        "healthcheck_port": 8089,
        "api_port": 8089,
    },
    "elastic": {
        "container_name": "shikari-elastic",
        "ports": {"api": 9200, "transport": 9300},
        "healthcheck_port": 9200,
        "api_port": 9200,
    },
    "secops": {
        "container_name": "shikari-secops",
        "ports": {"api": 8081},
        "healthcheck_port": 8081,
        "api_port": 8081,
    },
    "mde": {
        "container_name": "shikari-mde",
        "ports": {"api": 8082},
        "healthcheck_port": 8082,
        "api_port": 8082,
    },
}


@dataclass
class SIEMInstance:
    """Represents a running SIEM container instance"""
    vendor: str
    session_id: str
    container_id: str
    host: str
    port: int
    api_port: Optional[int] = None
    status: str = "starting"
    started_at: datetime = field(default_factory=datetime.utcnow)
    credentials: Dict[str, str] = field(default_factory=dict)
    from_compose: bool = False  # True if using docker-compose container

    def get_url(self) -> str:
        """Get the base URL for this SIEM instance"""
        return f"http://{self.host}:{self.port}"

    def get_api_url(self) -> str:
        """Get the API URL for this SIEM instance"""
        port = self.api_port or self.port
        return f"http://{self.host}:{port}"


class DockerSIEMManager:
    """Manages ephemeral SIEM containers for validation"""

    # Container configurations per vendor
    SIEM_CONFIGS = {
        "splunk": {
            "image": "splunk/splunk:latest",
            "ports": {"8000": "8000", "8089": "8089", "8088": "8088"},
            "environment": {
                "SPLUNK_START_ARGS": "--accept-license",
                "SPLUNK_PASSWORD": "Validation123!",
                "SPLUNK_HEC_TOKEN": "validation-hec-token",
            },
            "healthcheck_port": 8089,
            "api_port": 8089,
            "hec_port": 8088,
            "startup_timeout": 180,
            "memory_limit": "2g",
        },
        "elastic": {
            "image": "docker.elastic.co/elasticsearch/elasticsearch:8.11.0",
            "ports": {"9200": "9200", "9300": "9300"},
            "environment": {
                "discovery.type": "single-node",
                "xpack.security.enabled": "false",
                "ES_JAVA_OPTS": "-Xms512m -Xmx512m",
            },
            "healthcheck_port": 9200,
            "api_port": 9200,
            "startup_timeout": 120,
            "memory_limit": "1g",
        },
        "secops": {
            "image": "shikari-secops-simulator:latest",
            "build_context": "shikari/siem/secops",
            "ports": {"8080": "8080"},
            "environment": {},
            "healthcheck_port": 8080,
            "api_port": 8080,
            "startup_timeout": 30,
            "memory_limit": "512m",
        },
        "mde": {
            "image": "shikari-mde-simulator:latest",
            "build_context": "shikari/siem/mde",
            "ports": {"8080": "8080"},
            "environment": {},
            "healthcheck_port": 8080,
            "api_port": 8080,
            "startup_timeout": 30,
            "memory_limit": "512m",
        },
    }

    def __init__(self, project_root: Optional[str] = None):
        """
        Initialize Docker SIEM Manager.

        Args:
            project_root: Path to project root (for Docker context)
        """
        self.project_root = Path(project_root) if project_root else Path(__file__).parent.parent.parent
        self.active_instances: Dict[str, SIEMInstance] = {}
        self._verify_docker()

    def _verify_docker(self):
        """Verify Docker is available and running"""
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise RuntimeError("Docker is not running")
        except FileNotFoundError:
            raise RuntimeError("Docker is not installed")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Docker is not responding")

    def _get_session_key(self, vendor: str, session_id: str) -> str:
        """Generate a unique key for tracking instances"""
        return f"{vendor}_{session_id}"

    def _get_container_name(self, vendor: str, session_id: str) -> str:
        """Generate a unique container name"""
        short_id = session_id[:8] if len(session_id) > 8 else session_id
        return f"shikari-validation-{vendor}-{short_id}"

    def _check_compose_container(self, vendor: str) -> Optional[SIEMInstance]:
        """
        Check if a docker-compose profile container is running for this vendor.

        Returns:
            SIEMInstance if a running compose container is found, None otherwise
        """
        if vendor not in COMPOSE_CONTAINERS:
            return None

        compose_config = COMPOSE_CONTAINERS[vendor]
        container_name = compose_config["container_name"]

        try:
            # Check if container exists and is running
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", container_name],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0 or result.stdout.strip() != "true":
                logger.debug(f"Compose container {container_name} not running")
                return None

            # Get container ID
            id_result = subprocess.run(
                ["docker", "inspect", "--format", "{{.Id}}", container_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            container_id = id_result.stdout.strip()[:12] if id_result.returncode == 0 else container_name

            # Container is running - create instance
            api_port = compose_config["api_port"]
            first_port = list(compose_config["ports"].values())[0]

            instance = SIEMInstance(
                vendor=vendor,
                session_id="compose",  # Special session ID for compose containers
                container_id=container_id,
                host="localhost",
                port=first_port,
                api_port=api_port,
                status="running",
                credentials=self._get_credentials(vendor),
                from_compose=True,
            )

            logger.info(f"Found running docker-compose container: {container_name} (port {api_port})")
            return instance

        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout checking compose container {container_name}")
            return None
        except Exception as e:
            logger.debug(f"Error checking compose container {container_name}: {e}")
            return None

    def get_compose_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Get status of all docker-compose profile containers.

        Returns:
            Dict mapping vendor to status info
        """
        status = {}
        for vendor in COMPOSE_CONTAINERS.keys():
            instance = self._check_compose_container(vendor)
            if instance:
                status[vendor] = {
                    "available": True,
                    "container_name": COMPOSE_CONTAINERS[vendor]["container_name"],
                    "api_port": instance.api_port,
                    "status": "running",
                }
            else:
                status[vendor] = {
                    "available": False,
                    "container_name": COMPOSE_CONTAINERS[vendor]["container_name"],
                    "status": "stopped",
                    "start_command": f"docker-compose --profile {vendor} up -d",
                }
        return status

    def start_siem(
        self,
        vendor: str,
        session_id: Optional[str] = None,
        port_offset: int = 0,
        prefer_compose: bool = True
    ) -> SIEMInstance:
        """
        Start a SIEM container for validation.

        First checks for running docker-compose profile containers.
        If not found, spawns an ephemeral container.

        Args:
            vendor: SIEM vendor (splunk, elastic, secops, mde)
            session_id: Unique session identifier (generated if not provided)
            port_offset: Offset for port mapping to avoid conflicts
            prefer_compose: If True, prefer docker-compose containers over ephemeral

        Returns:
            SIEMInstance with connection details
        """
        vendor = vendor.lower()
        if vendor not in self.SIEM_CONFIGS:
            raise ValueError(f"Unsupported vendor: {vendor}. Supported: {list(self.SIEM_CONFIGS.keys())}")

        session_id = session_id or str(uuid.uuid4())
        session_key = self._get_session_key(vendor, session_id)

        # Check if already have an instance for this session
        if session_key in self.active_instances:
            existing = self.active_instances[session_key]
            if existing.status == "running":
                logger.info(f"SIEM {vendor} already running for session {session_id}")
                return existing

        # Check for docker-compose profile container first
        if prefer_compose:
            compose_instance = self._check_compose_container(vendor)
            if compose_instance:
                # Store with session key so we can track it
                compose_instance.session_id = session_id
                self.active_instances[session_key] = compose_instance
                logger.info(f"Using docker-compose {vendor} container for session {session_id}")
                return compose_instance

        # No compose container - spawn ephemeral one
        logger.info(f"No docker-compose container for {vendor}, spawning ephemeral container")

        config = self.SIEM_CONFIGS[vendor]
        container_name = self._get_container_name(vendor, session_id)

        # Build simulator images if needed
        if "build_context" in config:
            self._build_simulator_image(vendor, config)

        # Calculate ports with offset
        port_mappings = {}
        first_host_port = None
        api_host_port = None

        for container_port, base_host_port in config["ports"].items():
            host_port = int(base_host_port) + port_offset
            port_mappings[container_port] = str(host_port)
            if first_host_port is None:
                first_host_port = host_port
            if container_port == str(config["healthcheck_port"]):
                api_host_port = host_port

        # Build docker run command
        cmd = [
            "docker", "run", "-d",
            "--name", container_name,
            "--memory", config["memory_limit"],
            "--rm",  # Auto-remove when stopped
        ]

        # Add port mappings
        for container_port, host_port in port_mappings.items():
            cmd.extend(["-p", f"{host_port}:{container_port}"])

        # Add environment variables
        for key, value in config["environment"].items():
            cmd.extend(["-e", f"{key}={value}"])

        # Add image
        cmd.append(config["image"])

        logger.info(f"Starting {vendor} container: {container_name}")
        logger.debug(f"Command: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                raise RuntimeError(f"Failed to start container: {result.stderr}")

            container_id = result.stdout.strip()

            instance = SIEMInstance(
                vendor=vendor,
                session_id=session_id,
                container_id=container_id,
                host="localhost",
                port=first_host_port,
                api_port=api_host_port,
                status="starting",
                credentials=self._get_credentials(vendor),
            )

            self.active_instances[session_key] = instance

            # Wait for container to be healthy
            if self._wait_for_health(instance, config["startup_timeout"]):
                instance.status = "running"
                logger.info(f"{vendor} container ready at port {first_host_port}")
            else:
                instance.status = "unhealthy"
                logger.warning(f"{vendor} container started but health check failed")

            return instance

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Timeout starting {vendor} container")
        except Exception as e:
            logger.error(f"Error starting {vendor} container: {e}")
            raise

    def _build_simulator_image(self, vendor: str, config: Dict):
        """Build simulator Docker image if it doesn't exist"""
        image_name = config["image"]

        # Check if image exists
        result = subprocess.run(
            ["docker", "images", "-q", image_name],
            capture_output=True,
            text=True
        )

        if result.stdout.strip():
            logger.debug(f"Image {image_name} already exists")
            return

        build_context = self.project_root / config["build_context"]
        if not build_context.exists():
            logger.warning(f"Build context not found: {build_context}")
            logger.info(f"Creating placeholder simulator for {vendor}")
            self._create_simulator_placeholder(vendor, build_context)

        logger.info(f"Building {image_name} from {build_context}")

        result = subprocess.run(
            ["docker", "build", "-t", image_name, str(build_context)],
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            raise RuntimeError(f"Failed to build {image_name}: {result.stderr}")

    def _create_simulator_placeholder(self, vendor: str, build_context: Path):
        """Create a minimal simulator placeholder"""
        build_context.mkdir(parents=True, exist_ok=True)

        # Create Dockerfile
        dockerfile = build_context / "Dockerfile"
        dockerfile.write_text(f"""FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY simulator.py .
EXPOSE 8080
CMD ["python", "simulator.py"]
""")

        # Create requirements.txt
        requirements = build_context / "requirements.txt"
        requirements.write_text("flask>=3.0.0\n")

        # Create placeholder simulator
        simulator = build_context / "simulator.py"
        simulator.write_text(f'''"""
{vendor.upper()} Simulator - Placeholder
Replace with full implementation
"""
from flask import Flask, jsonify, request
import json

app = Flask(__name__)

# In-memory event store
events = []

@app.route("/health", methods=["GET"])
def health():
    return jsonify({{"status": "healthy", "vendor": "{vendor}"}})

@app.route("/api/events", methods=["POST"])
def ingest_events():
    data = request.get_json()
    if isinstance(data, list):
        events.extend(data)
    else:
        events.append(data)
    return jsonify({{"ingested": len(data) if isinstance(data, list) else 1}})

@app.route("/api/query", methods=["POST"])
def execute_query():
    query = request.get_json().get("query", "")
    # Placeholder: return all events
    return jsonify({{"results": events, "query": query}})

@app.route("/api/clear", methods=["POST"])
def clear_events():
    events.clear()
    return jsonify({{"cleared": True}})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
''')

    def _wait_for_health(self, instance: SIEMInstance, timeout: int) -> bool:
        """Wait for container to be healthy"""
        start_time = time.time()
        health_url = f"{instance.get_api_url()}/health"

        # Vendor-specific health endpoints
        if instance.vendor == "splunk":
            health_url = f"https://localhost:{instance.api_port}/services/server/health/splunkd"
        elif instance.vendor == "elastic":
            health_url = f"http://localhost:{instance.api_port}/_cluster/health"

        session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.5)
        session.mount("http://", HTTPAdapter(max_retries=retries))
        session.mount("https://", HTTPAdapter(max_retries=retries))

        while time.time() - start_time < timeout:
            try:
                if instance.vendor == "splunk":
                    # Splunk uses HTTPS with self-signed cert
                    response = session.get(
                        health_url,
                        auth=(instance.credentials.get("username", "admin"),
                              instance.credentials.get("password", "")),
                        verify=False,
                        timeout=5
                    )
                else:
                    response = session.get(health_url, timeout=5)

                if response.status_code in (200, 201, 503):  # 503 for Elastic when starting
                    if instance.vendor == "elastic":
                        data = response.json()
                        if data.get("status") in ("green", "yellow"):
                            return True
                    else:
                        return True

            except requests.exceptions.RequestException as e:
                logger.debug(f"Health check pending for {instance.vendor}: {e}")

            time.sleep(2)

        return False

    def _get_credentials(self, vendor: str) -> Dict[str, str]:
        """Get default credentials for a vendor"""
        if vendor == "splunk":
            return {
                "username": "admin",
                "password": "Validation123!",
                "hec_token": "validation-hec-token",
            }
        elif vendor == "elastic":
            return {"username": "elastic", "password": ""}
        return {}

    def stop_siem(self, session_id: str, vendor: Optional[str] = None) -> None:
        """
        Stop SIEM container(s) for a session.

        Note: Docker-compose containers are NOT stopped - they are managed separately.
        Only ephemeral containers spawned by this manager are stopped.

        Args:
            session_id: Session identifier
            vendor: Specific vendor to stop (all if not specified)
        """
        vendors_to_stop = [vendor] if vendor else list(self.SIEM_CONFIGS.keys())

        for v in vendors_to_stop:
            session_key = self._get_session_key(v, session_id)
            if session_key in self.active_instances:
                instance = self.active_instances[session_key]

                # Don't stop docker-compose containers - just remove from tracking
                if instance.from_compose:
                    logger.info(f"Releasing docker-compose {v} container (not stopping)")
                    del self.active_instances[session_key]
                    continue

                # Stop ephemeral container
                container_name = self._get_container_name(v, session_id)
                logger.info(f"Stopping ephemeral {v} container: {container_name}")

                try:
                    subprocess.run(
                        ["docker", "stop", container_name],
                        capture_output=True,
                        timeout=30
                    )
                except subprocess.TimeoutExpired:
                    logger.warning(f"Timeout stopping {container_name}, forcing kill")
                    subprocess.run(["docker", "kill", container_name], capture_output=True)

                del self.active_instances[session_key]

    def stop_all(self) -> None:
        """Stop all active SIEM containers"""
        for session_key in list(self.active_instances.keys()):
            vendor, session_id = session_key.split("_", 1)
            self.stop_siem(session_id, vendor)

    def stop_compose_container(self, vendor: str) -> Dict[str, Any]:
        """
        Stop a docker-compose profile container.

        Args:
            vendor: SIEM vendor to stop (splunk, elastic, secops, mde)

        Returns:
            Status dict with success/error
        """
        if vendor not in COMPOSE_CONTAINERS:
            return {
                "success": False,
                "error": f"Unknown vendor: {vendor}. Valid: {list(COMPOSE_CONTAINERS.keys())}",
            }

        container_name = COMPOSE_CONTAINERS[vendor]["container_name"]

        # Check if container is running
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", container_name],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0 or result.stdout.strip() != "true":
                return {
                    "success": True,
                    "message": f"Container {container_name} is not running",
                    "was_running": False,
                }

            # Stop the container
            logger.info(f"Stopping docker-compose container: {container_name}")
            stop_result = subprocess.run(
                ["docker", "stop", container_name],
                capture_output=True,
                text=True,
                timeout=60
            )

            if stop_result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to stop {container_name}: {stop_result.stderr}",
                }

            # Remove from active instances if tracked
            for session_key in list(self.active_instances.keys()):
                instance = self.active_instances[session_key]
                if instance.vendor == vendor and instance.from_compose:
                    del self.active_instances[session_key]

            return {
                "success": True,
                "message": f"Stopped container {container_name}",
                "was_running": True,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Timeout stopping {container_name}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }

    def stop_all_compose_containers(self) -> Dict[str, Any]:
        """
        Stop all docker-compose profile containers.

        Returns:
            Status dict with results per vendor
        """
        results = {}
        for vendor in COMPOSE_CONTAINERS.keys():
            results[vendor] = self.stop_compose_container(vendor)

        stopped_count = sum(1 for r in results.values() if r.get("was_running"))

        return {
            "success": True,
            "message": f"Stopped {stopped_count} containers",
            "results": results,
        }

    def get_status(self, session_id: str) -> Dict[str, Any]:
        """
        Get status of all SIEM containers for a session.

        Args:
            session_id: Session identifier

        Returns:
            Dict mapping vendor to status info
        """
        status = {}
        for vendor in self.SIEM_CONFIGS.keys():
            session_key = self._get_session_key(vendor, session_id)
            if session_key in self.active_instances:
                instance = self.active_instances[session_key]
                status[vendor] = {
                    "status": instance.status,
                    "url": instance.get_url(),
                    "api_url": instance.get_api_url(),
                    "started_at": instance.started_at.isoformat(),
                    "from_compose": instance.from_compose,
                    "container_type": "docker-compose" if instance.from_compose else "ephemeral",
                }
            else:
                # Check if compose container is available even if not in this session
                compose_instance = self._check_compose_container(vendor)
                if compose_instance:
                    status[vendor] = {
                        "status": "available",
                        "url": compose_instance.get_url(),
                        "api_url": compose_instance.get_api_url(),
                        "from_compose": True,
                        "container_type": "docker-compose",
                        "note": "Available via docker-compose profile",
                    }
                else:
                    status[vendor] = {
                        "status": "stopped",
                        "from_compose": False,
                        "start_hint": f"Run: docker-compose --profile {vendor} up -d",
                    }

        return status

    def ingest_events(
        self,
        session_id: str,
        vendor: str,
        events: List[Dict]
    ) -> bool:
        """
        Ingest events into a running SIEM container.

        Args:
            session_id: Session identifier
            vendor: SIEM vendor
            events: List of event dictionaries

        Returns:
            True if ingestion successful
        """
        session_key = self._get_session_key(vendor, session_id)
        if session_key not in self.active_instances:
            raise ValueError(f"No running {vendor} instance for session {session_id}")

        instance = self.active_instances[session_key]

        if vendor == "splunk":
            return self._ingest_splunk(instance, events)
        elif vendor == "elastic":
            return self._ingest_elastic(instance, events)
        else:
            return self._ingest_simulator(instance, events)

    def _ingest_splunk(self, instance: SIEMInstance, events: List[Dict]) -> bool:
        """Ingest events into Splunk via HEC"""
        hec_port = int(list(self.SIEM_CONFIGS["splunk"]["ports"].keys())[2])  # HEC port
        hec_url = f"http://localhost:{instance.port + (hec_port - 8000)}/services/collector/event"

        headers = {
            "Authorization": f"Splunk {instance.credentials.get('hec_token', '')}",
            "Content-Type": "application/json",
        }

        try:
            for event in events:
                payload = {"event": event, "sourcetype": "validation_test"}
                response = requests.post(hec_url, headers=headers, json=payload, timeout=10)
                if response.status_code not in (200, 201):
                    logger.error(f"Splunk HEC error: {response.text}")
                    return False
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Splunk ingestion error: {e}")
            return False

    def _ingest_elastic(self, instance: SIEMInstance, events: List[Dict]) -> bool:
        """Ingest events into Elasticsearch via Bulk API"""
        bulk_url = f"{instance.get_api_url()}/validation-events/_bulk"

        # Build bulk request body
        bulk_body = ""
        for event in events:
            bulk_body += json.dumps({"index": {}}) + "\n"
            bulk_body += json.dumps(event) + "\n"

        headers = {"Content-Type": "application/x-ndjson"}

        try:
            response = requests.post(bulk_url, headers=headers, data=bulk_body, timeout=30)
            if response.status_code not in (200, 201):
                logger.error(f"Elasticsearch bulk error: {response.text}")
                return False
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Elasticsearch ingestion error: {e}")
            return False

    def _ingest_simulator(self, instance: SIEMInstance, events: List[Dict]) -> bool:
        """Ingest events into simulator via REST API"""
        api_url = f"{instance.get_api_url()}/api/events"

        try:
            response = requests.post(api_url, json=events, timeout=10)
            if response.status_code not in (200, 201):
                logger.error(f"Simulator ingestion error: {response.text}")
                return False
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Simulator ingestion error: {e}")
            return False

    def execute_query(
        self,
        session_id: str,
        vendor: str,
        query: str
    ) -> Dict[str, Any]:
        """
        Execute a query against a running SIEM container.

        Args:
            session_id: Session identifier
            vendor: SIEM vendor
            query: Query string in vendor-specific syntax

        Returns:
            Query results dict
        """
        session_key = self._get_session_key(vendor, session_id)
        if session_key not in self.active_instances:
            raise ValueError(f"No running {vendor} instance for session {session_id}")

        instance = self.active_instances[session_key]

        if vendor == "splunk":
            return self._query_splunk(instance, query)
        elif vendor == "elastic":
            return self._query_elastic(instance, query)
        else:
            return self._query_simulator(instance, query)

    def _query_splunk(self, instance: SIEMInstance, query: str) -> Dict[str, Any]:
        """Execute SPL query against Splunk"""
        from shikari.query.splunk import SplunkClient

        try:
            client = SplunkClient(
                host="localhost",
                port=instance.api_port,
                username=instance.credentials.get("username", "admin"),
                password=instance.credentials.get("password", ""),
                use_https=True,
            )
            return client.execute_query(query)
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _query_elastic(self, instance: SIEMInstance, query: str) -> Dict[str, Any]:
        """Execute query against Elasticsearch"""
        # For Elasticsearch, query should be JSON Query DSL
        search_url = f"{instance.get_api_url()}/validation-events/_search"

        try:
            if isinstance(query, str):
                # Simple query string search
                payload = {"query": {"query_string": {"query": query}}}
            else:
                payload = query

            response = requests.post(
                search_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "success",
                    "results": [hit["_source"] for hit in data.get("hits", {}).get("hits", [])],
                    "stats": {"total": data.get("hits", {}).get("total", {}).get("value", 0)},
                }
            else:
                return {"status": "error", "error": response.text}

        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e)}

    def _query_simulator(self, instance: SIEMInstance, query: str) -> Dict[str, Any]:
        """Execute query against simulator"""
        api_url = f"{instance.get_api_url()}/api/query"

        try:
            response = requests.post(
                api_url,
                json={"query": query},
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "success",
                    "results": data.get("results", []),
                    "stats": {"total": len(data.get("results", []))},
                }
            else:
                return {"status": "error", "error": response.text}

        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e)}

    def health_check(self, vendor: str, session_id: str) -> bool:
        """Check if a SIEM instance is healthy"""
        session_key = self._get_session_key(vendor, session_id)
        if session_key not in self.active_instances:
            return False

        instance = self.active_instances[session_key]
        return instance.status == "running"
