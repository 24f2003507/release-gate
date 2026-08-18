from flask import Flask, request, jsonify
import re

app = Flask(__name__)

EXPECTED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none"
}

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


@app.post("/release-gate")
def release_gate():
    data = request.get_json()

    violations = []

    workflow = data.get("workflow", {})
    image = data.get("image", {})

    # 1. Permissions must be EXACTLY the required permissions
    permissions = workflow.get("permissions", {})

    if permissions != EXPECTED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # 2. Pull requests must use pull_request
    event = data.get("event")

    if event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

        # Tests, matrix and fail-fast requirements
        if (
            workflow.get("testsPassed") is not True
            or workflow.get("matrixComplete") is not True
            or workflow.get("failFast") is not False
        ):
            violations.append("TESTS_INCOMPLETE")

    # 3. Action pinning
    actions = workflow.get("actions", [])

    for action in actions:
        owner = action.get("owner")
        ref = action.get("ref", "")

        # actions/* may use version tags
        if owner == "actions":
            continue

        # Third-party actions require a full lowercase 40-char SHA
        if not SHA_PATTERN.fullmatch(ref):
            violations.append("MUTABLE_ACTION")
            break

    # 4. Image hardening
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 5. Production-specific requirements
    if data.get("target") == "production":

        if (
            event != "push"
            or data.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # Decision is promote ONLY when there are no violations
    decision = "promote" if not violations else "block"

    return jsonify({
        "decision": decision,
        "violations": violations
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)