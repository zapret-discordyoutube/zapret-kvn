"""Подделка ``sing-box tools browser-fetch --serve`` для тестов клиента."""

import base64
import json
import sys

for line in sys.stdin:
    request = json.loads(line)
    url = request["url"]
    if "crash" in url:
        sys.exit(3)
    if "nolib" in url:
        reply = {"id": request["id"], "error": "browserfetch unavailable: cronet: library not found", "unavailable": True}
    elif "fail" in url:
        reply = {"id": request["id"], "error": "net::ERR_CONNECTION_RESET"}
    else:
        echo = json.dumps({"method": request.get("method"), "headers": request.get("headers"),
                           "body": request.get("body", "")}).encode()
        reply = {"id": request["id"], "status": 200, "headers": [["Content-Type", "application/json"]],
                 "body": base64.b64encode(echo).decode(), "user_agent": "Chrome/150"}
    sys.stdout.write(json.dumps(reply) + "\n")
    sys.stdout.flush()
