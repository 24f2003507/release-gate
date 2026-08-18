from app import app


def safe_payload():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {
                "contents": "read",
                "packages": "write",
                "id-token": "none"
            },
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {
                    "owner": "actions",
                    "name": "checkout",
                    "ref": "v4"
                },
                {
                    "owner": "some-user",
                    "name": "some-action",
                    "ref": "0123456789abcdef0123456789abcdef01234567"
                }
            ]
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True
        }
    }


def test_safe_request():
    client = app.test_client()

    response = client.post("/release-gate", json=safe_payload())

    assert response.status_code == 200

    data = response.get_json()

    assert data["decision"] == "promote"
    assert data["violations"] == []


def test_excess_permission():
    client = app.test_client()

    payload = safe_payload()
    payload["workflow"]["permissions"]["issues"] = "write"

    response = client.post("/release-gate", json=payload)
    data = response.get_json()

    assert data["decision"] == "block"
    assert "EXCESS_PERMISSION" in data["violations"]


def test_unsafe_pr_trigger():
    client = app.test_client()

    payload = safe_payload()
    payload["workflow"]["trigger"] = "pull_request_target"

    response = client.post("/release-gate", json=payload)
    data = response.get_json()

    assert data["decision"] == "block"
    assert "UNSAFE_PR_TRIGGER" in data["violations"]


def test_incomplete_tests():
    client = app.test_client()

    payload = safe_payload()
    payload["workflow"]["testsPassed"] = False

    response = client.post("/release-gate", json=payload)
    data = response.get_json()

    assert data["decision"] == "block"
    assert "TESTS_INCOMPLETE" in data["violations"]


def test_mutable_third_party_action():
    client = app.test_client()

    payload = safe_payload()
    payload["workflow"]["actions"][1]["ref"] = "v1"

    response = client.post("/release-gate", json=payload)
    data = response.get_json()

    assert data["decision"] == "block"
    assert "MUTABLE_ACTION" in data["violations"]


def test_image_failures():
    client = app.test_client()

    payload = safe_payload()

    payload["image"]["multiStage"] = False
    payload["image"]["runsAsRoot"] = True
    payload["image"]["secretMode"] = "copy"
    payload["image"]["criticalVulnerabilities"] = 2
    payload["image"]["digestPinned"] = False

    response = client.post("/release-gate", json=payload)
    data = response.get_json()

    assert data["decision"] == "block"

    assert "SINGLE_STAGE_IMAGE" in data["violations"]
    assert "ROOT_RUNTIME" in data["violations"]
    assert "SECRET_IN_LAYER" in data["violations"]
    assert "CRITICAL_CVE" in data["violations"]
    assert "UNPINNED_IMAGE" in data["violations"]


def test_invalid_production():
    client = app.test_client()

    payload = safe_payload()

    payload["target"] = "production"
    payload["event"] = "pull_request"
    payload["ref"] = "refs/heads/feature"

    response = client.post("/release-gate", json=payload)
    data = response.get_json()

    assert data["decision"] == "block"
    assert "INVALID_PRODUCTION_REF" in data["violations"]
    assert "APPROVAL_REQUIRED" in data["violations"]


def test_valid_production():
    client = app.test_client()

    payload = safe_payload()

    payload["target"] = "production"
    payload["event"] = "push"
    payload["ref"] = "refs/heads/main"
    payload["workflow"]["trigger"] = "push"
    payload["workflow"]["environmentApproval"] = True

    response = client.post("/release-gate", json=payload)
    data = response.get_json()

    assert data["decision"] == "promote"
    assert data["violations"] == []