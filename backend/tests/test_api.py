from fastapi.testclient import TestClient

from app.main import app


def test_health_endpoint():
    client = TestClient(app)
    response = client.get('/api/health')
    assert response.status_code == 200
    assert response.json()['ok'] is True


def test_settings_roundtrip():
    client = TestClient(app)
    payload = {
        "user_agent": "fixed-agent",
        "rotate_user_agents": ["a", "b"],
        "headers": {"X-Test": "1"},
        "proxy": "http://host.docker.internal:8080",
    }
    response = client.put('/api/settings', json=payload)
    assert response.status_code == 200
    assert response.json()["headers"] == {"X-Test": "1"}
    assert client.get('/api/settings').json()["proxy"] == payload["proxy"]
