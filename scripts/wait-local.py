import time
from production_approval.authorization.isolation import LocalClients, ACCOUNT
from botocore.exceptions import EndpointConnectionError, ConnectionClosedError

for attempt in range(40):
    try:
        result = LocalClients().client("sts").get_caller_identity()
        if result["Account"] != ACCOUNT:
            raise RuntimeError("Unexpected emulator account")
        break
    except (EndpointConnectionError, ConnectionClosedError):
        if attempt == 39:
            raise
        time.sleep(0.1)
