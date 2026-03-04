"""
Google SecOps Simulator

Simulates the Google SecOps detection API for validation testing.
Accepts UDM-formatted events and executes YARA-L rules.
"""

from flask import Flask, jsonify, request
from datetime import datetime
import json
import logging
from yaral_parser import YaralParser

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# In-memory event store
events = []
parser = YaralParser()


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "vendor": "secops",
        "simulator": True,
        "event_count": len(events),
        "timestamp": datetime.utcnow().isoformat(),
    })


@app.route("/api/events", methods=["POST"])
def ingest_events():
    """
    Ingest UDM-formatted events.

    Expected format:
    [
        {
            "metadata": {"event_type": "PROCESS_LAUNCH", ...},
            "principal": {...},
            "target": {"process": {"command_line": "...", "file": {...}}, ...},
            ...
        }
    ]
    """
    try:
        data = request.get_json()

        if isinstance(data, list):
            events.extend(data)
            count = len(data)
        else:
            events.append(data)
            count = 1

        logger.info(f"Ingested {count} events. Total: {len(events)}")

        return jsonify({
            "status": "success",
            "ingested": count,
            "total_events": len(events),
        })

    except Exception as e:
        logger.error(f"Ingestion error: {e}")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/events", methods=["GET"])
def list_events():
    """List all stored events"""
    return jsonify({
        "events": events,
        "count": len(events),
    })


@app.route("/api/query", methods=["POST"])
def execute_query():
    """
    Execute a YARA-L rule against stored events.

    Request body:
    {
        "query": "rule MyRule {...}"
    }

    Response:
    {
        "status": "success",
        "results": [...matching events...],
        "rule_name": "MyRule",
        "match_count": N
    }
    """
    try:
        data = request.get_json()
        query = data.get("query", "")

        if not query:
            return jsonify({"status": "error", "error": "No query provided"}), 400

        logger.info(f"Executing YARA-L query against {len(events)} events")

        # Parse the YARA-L rule
        rule = parser.parse(query)
        logger.info(f"Parsed rule: {rule.name}")

        # Execute against events
        matches = parser.execute(rule, events)

        return jsonify({
            "status": "success",
            "results": matches,
            "rule_name": rule.name,
            "match_count": len(matches),
            "total_events": len(events),
            "meta": rule.meta,
        })

    except ValueError as e:
        logger.error(f"YARA-L parse error: {e}")
        return jsonify({"status": "error", "error": f"Parse error: {str(e)}"}), 400
    except Exception as e:
        logger.error(f"Query execution error: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/api/validate", methods=["POST"])
def validate_rule():
    """
    Validate a YARA-L rule syntax without executing.

    Request body:
    {
        "rule": "rule MyRule {...}"
    }
    """
    try:
        data = request.get_json()
        rule_text = data.get("rule", "")

        if not rule_text:
            return jsonify({"valid": False, "error": "No rule provided"}), 400

        # Try to parse the rule
        rule = parser.parse(rule_text)

        return jsonify({
            "valid": True,
            "rule_name": rule.name,
            "meta": rule.meta,
            "event_conditions": len(rule.events),
            "condition": rule.condition,
        })

    except ValueError as e:
        return jsonify({"valid": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 500


@app.route("/api/clear", methods=["POST"])
def clear_events():
    """Clear all stored events"""
    events.clear()
    logger.info("Events cleared")
    return jsonify({"status": "success", "cleared": True})


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Get statistics about stored events"""
    event_types = {}
    for event in events:
        event_type = event.get("metadata", {}).get("event_type", "UNKNOWN")
        event_types[event_type] = event_types.get(event_type, 0) + 1

    return jsonify({
        "total_events": len(events),
        "event_types": event_types,
    })


if __name__ == "__main__":
    logger.info("Starting Google SecOps Simulator on port 8080")
    app.run(host="0.0.0.0", port=8080, debug=False)
