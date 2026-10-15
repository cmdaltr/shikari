"""Per-user AI providers and job assignment (GitHub #10)."""

from unittest.mock import MagicMock, patch

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from archer.ai import assignment
from archer.auth.encryption import encrypt_api_key
from archer.database.models import APIKey, Base, User

KEY = Fernet.generate_key()


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    for uid in (1, 2):
        session.add(User(id=uid, email=f"u{uid}@x", full_name="u", password_hash="x"))
    session.commit()
    with patch("archer.auth.encryption.get_encryption_key", return_value=KEY):
        yield session
    session.close()


def _key(db, user_id, platform, value):
    db.add(APIKey(user_id=user_id, platform=platform, encrypted_key=encrypt_api_key(value)))
    db.commit()


def _update(db, user_id, update):
    settings = assignment.load_settings(db, user_id)
    settings = assignment.apply_update(settings, update, assignment.configured_providers(db, user_id, settings))
    assignment.save_settings(db, user_id, settings)
    return settings


@pytest.mark.unit
def test_only_configured_providers_are_offered(db):
    assert assignment.configured_providers(db, 1) == []
    _key(db, 1, "anthropic", "sk-ant-1")
    _update(db, 1, {"local": {"endpoint": "http://localhost:11434/", "model": "qwen3:8b"}})
    providers = {p["id"]: p for p in assignment.configured_providers(db, 1)}
    assert set(providers) == {"anthropic", "local"}
    assert providers["anthropic"]["detection"] and not providers["local"]["detection"]
    # Another user's keys never show up
    assert assignment.configured_providers(db, 2) == []


@pytest.mark.unit
def test_each_job_has_its_own_provider_and_model(db):
    _key(db, 1, "anthropic", "sk-ant-1")
    _key(db, 1, "openai", "sk-oa-1")
    _update(db, 1, {"local": {"endpoint": "http://localhost:11434", "model": "qwen3:8b"}})
    _update(db, 1, {"ask": {"provider": "local", "model": "qwen3:8b"},
                    "detection": {"provider": "anthropic", "model": "claude-x"}})
    ask = assignment.resolve(db, 1, "ask")
    det = assignment.resolve(db, 1, "detection")
    assert (ask["provider"], ask["model"], ask["endpoint"]) == ("local", "qwen3:8b", "http://localhost:11434")
    assert (det["provider"], det["model"], det["api_key"]) == ("anthropic", "claude-x", "sk-ant-1")
    assert det["max_calls"] == assignment.DEFAULT_MAX_DETECTION_CALLS
    # A hunt can override the assignment with another configured provider
    assert assignment.resolve(db, 1, "detection", "openai")["api_key"] == "sk-oa-1"
    # ...but not with one the user hasn't configured
    assert assignment.resolve(db, 1, "detection", "grok") is None


@pytest.mark.unit
def test_local_models_are_ask_only(db):
    _update(db, 1, {"local": {"endpoint": "http://localhost:11434", "model": "qwen3:8b"}})
    with pytest.raises(ValueError, match="#9"):
        _update(db, 1, {"detection": {"provider": "local"}})
    assert assignment.resolve(db, 1, "detection", "local") is None
    with pytest.raises(ValueError):
        _update(db, 1, {"remember": {"provider": "local"}})


@pytest.mark.unit
def test_assignment_to_a_removed_key_is_dropped(db):
    _key(db, 1, "anthropic", "sk-ant-1")
    _update(db, 1, {"detection": {"provider": "anthropic"}, "remember": {"provider": "anthropic"}})
    db.query(APIKey).delete()
    db.commit()
    settings = _update(db, 1, {})
    assert settings["detection"] is None and settings["remember"] is None


@pytest.mark.unit
def test_remembering_no_ai_is_kept(db):
    settings = _update(db, 1, {"remember": {"provider": None}})
    assert settings["remember"] == {"provider": None, "model": ""}
    assert _update(db, 1, {"remember": None})["remember"] is None


@pytest.mark.unit
def test_call_cap_is_bounded(db):
    assert _update(db, 1, {"max_detection_calls": 10})["max_detection_calls"] == 10
    with pytest.raises(ValueError):
        _update(db, 1, {"max_detection_calls": 0})


@pytest.mark.unit
def test_probe_only_accepts_a_base_url():
    assert not assignment.probe_local("file:///etc/passwd")["ok"]
    assert not assignment.probe_local("http://localhost:11434/api/generate")["ok"]


@pytest.mark.unit
def test_detection_generation_goes_through_the_factory():
    # Every cloud provider (not just Anthropic/OpenAI) works for detection generation
    from archer.build import llm_queries

    llm = MagicMock()
    llm.generate.return_value = MagicMock(content='{"queries": []}')
    config = assignment.detection_llm_config({"provider": "deepseek", "api_key": "k", "model": "", "label": "DeepSeek"})
    with patch("archer.ai.assignment.create_llm", return_value=llm) as create:
        assert llm_queries.call_llm("prompt", config) == '{"queries": []}'
    assert create.call_args.args[0]["provider"] == "deepseek"


@pytest.mark.unit
def test_run_stops_calling_the_llm_at_the_cap(capsys):
    from archer.build import detections

    config = {"max_calls": 2, "label": "X"}
    with patch("archer.build.llm_queries.generate_llm_queries", return_value=[]) as gen:
        for _ in range(4):
            detections._run_bespoke_generation({"technique_id": "T1"}, [], "llm", config)
    assert gen.call_count == 2
    assert capsys.readouterr().out.count("LLM call limit") == 1


@pytest.mark.unit
def test_intel_only_techniques_spend_no_llm_call():
    from archer.build import detections

    config = {"max_calls": 5, "label": "X"}
    with patch("archer.build.llm_queries.generate_llm_queries", return_value=[]) as gen:
        # Phishing for Information: email and web logs see it, so it's worth a call
        detections._run_bespoke_generation({"technique_id": "T1598", "tactic": "Reconnaissance"}, [], "llm", config)
        # Acquire Infrastructure: adversary-side, intel only
        detections._run_bespoke_generation({"technique_id": "T1583", "tactic": "resource-development"}, [], "llm", config)
        detections._run_bespoke_generation({"technique_id": "T1566", "tactic": "Reconnaissance, Initial Access"}, [], "llm", config)
    assert gen.call_count == 2
    assert config["_calls"] == 2


@pytest.mark.unit
def test_anthropic_drops_parameters_a_model_refuses():
    import anthropic
    import httpx

    from archer.ai.llm.providers import _create_message

    def refuse(message):
        response = httpx.Response(400, request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"))
        return anthropic.BadRequestError(message, response=response, body=None)

    client = MagicMock()
    client.messages.create.side_effect = [refuse("`temperature` is deprecated for this model."),
                                          refuse('"thinking.type.between_tools" is not supported'), "ok"]
    kwargs = {"model": "m", "temperature": 0.2, "thinking": {"type": "between_tools"}}
    assert _create_message(client, kwargs) == "ok"
    assert "temperature" not in client.messages.create.call_args.kwargs
    assert "thinking" not in client.messages.create.call_args.kwargs
