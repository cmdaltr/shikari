"""
Microsoft Defender for Endpoint (MDE) Simulator

Simulates the MDE Advanced Hunting API for validation testing.
Accepts device event JSON and executes KQL-like queries.
"""

from flask import Flask, jsonify, request
from datetime import datetime
import json
import logging
from kql_parser import KqlParser

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# In-memory event store (organized by table)
events = {
    "DeviceProcessEvents": [],
    "DeviceNetworkEvents": [],
    "DeviceFileEvents": [],
    "DeviceRegistryEvents": [],
    "DeviceLogonEvents": [],
    "DeviceImageLoadEvents": [],
    "DeviceEvents": [],
}

parser = KqlParser()


def infer_table(event: dict) -> str:
    """Infer the MDE table based on event structure"""
    if "ProcessCommandLine" in event or "FileName" in event:
        if "RemoteIP" in event or "RemotePort" in event:
            return "DeviceNetworkEvents"
        elif "RegistryKey" in event:
            return "DeviceRegistryEvents"
        elif "LogonType" in event:
            return "DeviceLogonEvents"
        elif "FolderPath" in event and "SHA256" in event:
            if "InitiatingProcessFileName" in event and "FileName" in event:
                return "DeviceImageLoadEvents"
            return "DeviceFileEvents"
        return "DeviceProcessEvents"
    return "DeviceEvents"


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    total_events = sum(len(v) for v in events.values())
    return jsonify({
        "status": "healthy",
        "vendor": "mde",
        "simulator": True,
        "total_events": total_events,
        "tables": {k: len(v) for k, v in events.items()},
        "timestamp": datetime.utcnow().isoformat(),
    })


@app.route("/api/events", methods=["POST"])
def ingest_events():
    """
    Ingest MDE-formatted events.

    Events are automatically routed to appropriate tables based on their schema.

    Expected format:
    [
        {
            "Timestamp": "2024-01-01T00:00:00Z",
            "DeviceId": "...",
            "DeviceName": "...",
            "ProcessCommandLine": "...",
            ...
        }
    ]

    Or with explicit table:
    {
        "table": "DeviceProcessEvents",
        "events": [...]
    }
    """
    try:
        data = request.get_json()

        # Handle explicit table specification
        if isinstance(data, dict) and "table" in data:
            table = data["table"]
            table_events = data.get("events", [])
            if table in events:
                events[table].extend(table_events)
                logger.info(f"Ingested {len(table_events)} events into {table}")
                return jsonify({
                    "status": "success",
                    "ingested": len(table_events),
                    "table": table,
                })
            else:
                return jsonify({"status": "error", "error": f"Unknown table: {table}"}), 400

        # Auto-route events to tables
        if isinstance(data, list):
            event_list = data
        else:
            event_list = [data]

        counts = {}
        for event in event_list:
            table = infer_table(event)
            events[table].append(event)
            counts[table] = counts.get(table, 0) + 1

        logger.info(f"Ingested events: {counts}")

        return jsonify({
            "status": "success",
            "ingested": sum(counts.values()),
            "by_table": counts,
        })

    except Exception as e:
        logger.error(f"Ingestion error: {e}")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/events/<table>", methods=["GET"])
def list_table_events(table: str):
    """List events from a specific table"""
    if table not in events:
        return jsonify({"error": f"Unknown table: {table}"}), 404

    return jsonify({
        "table": table,
        "events": events[table],
        "count": len(events[table]),
    })


@app.route("/api/advancedhunting/run", methods=["POST"])
def advanced_hunting():
    """
    Execute an Advanced Hunting (KQL) query.

    This matches the MDE API signature for compatibility.

    Request body:
    {
        "Query": "DeviceProcessEvents | where FileName contains 'powershell'"
    }

    Response:
    {
        "Results": [...],
        "Stats": {...}
    }
    """
    try:
        data = request.get_json()
        query_str = data.get("Query", "")

        if not query_str:
            return jsonify({"error": "No query provided"}), 400

        logger.info(f"Executing KQL query: {query_str[:100]}...")

        # Parse the KQL query
        query = parser.parse(query_str)
        logger.info(f"Parsed query for table: {query.table}")

        # Execute against events
        results = parser.execute(query, events)

        return jsonify({
            "Results": results,
            "Stats": {
                "ExecutionTime": 0.001,
                "ResourceUsage": {"memory": 0, "cpu": 0},
                "ResultCount": len(results),
                "Table": query.table,
            }
        })

    except ValueError as e:
        logger.error(f"KQL parse error: {e}")
        return jsonify({"error": f"Parse error: {str(e)}"}), 400
    except Exception as e:
        logger.error(f"Query execution error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/query", methods=["POST"])
def execute_query():
    """
    Alternative query endpoint (simpler format).

    Request body:
    {
        "query": "DeviceProcessEvents | where FileName contains 'powershell'"
    }
    """
    try:
        data = request.get_json()
        query_str = data.get("query", "")

        if not query_str:
            return jsonify({"status": "error", "error": "No query provided"}), 400

        # Parse and execute
        query = parser.parse(query_str)
        results = parser.execute(query, events)

        return jsonify({
            "status": "success",
            "results": results,
            "match_count": len(results),
            "table": query.table,
        })

    except Exception as e:
        logger.error(f"Query error: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/api/validate", methods=["POST"])
def validate_query():
    """
    Validate a KQL query syntax without executing.

    Request body:
    {
        "query": "DeviceProcessEvents | where ..."
    }
    """
    try:
        data = request.get_json()
        query_str = data.get("query", "")

        if not query_str:
            return jsonify({"valid": False, "error": "No query provided"}), 400

        # Try to parse the query
        query = parser.parse(query_str)

        return jsonify({
            "valid": True,
            "table": query.table,
            "where_clauses": len(query.where_clauses),
            "has_project": query.project_fields is not None,
            "has_summarize": query.summarize is not None,
            "take_limit": query.take_limit,
        })

    except ValueError as e:
        return jsonify({"valid": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 500


@app.route("/api/clear", methods=["POST"])
def clear_events():
    """Clear all stored events"""
    for table in events:
        events[table].clear()
    logger.info("All events cleared")
    return jsonify({"status": "success", "cleared": True})


@app.route("/api/clear/<table>", methods=["POST"])
def clear_table(table: str):
    """Clear events from a specific table"""
    if table not in events:
        return jsonify({"error": f"Unknown table: {table}"}), 404

    events[table].clear()
    logger.info(f"Cleared {table}")
    return jsonify({"status": "success", "table": table, "cleared": True})


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Get statistics about stored events"""
    return jsonify({
        "total_events": sum(len(v) for v in events.values()),
        "tables": {k: len(v) for k, v in events.items()},
    })


@app.route("/api/tables", methods=["GET"])
def list_tables():
    """List available tables and their schemas"""
    return jsonify({
        "tables": list(parser.TABLE_SCHEMAS.keys()),
        "schemas": parser.TABLE_SCHEMAS,
    })


if __name__ == "__main__":
    logger.info("Starting MDE Simulator on port 8080")
    app.run(host="0.0.0.0", port=8080, debug=False)
