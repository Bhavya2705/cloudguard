
import csv
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

import boto3
from botocore.exceptions import BotoCoreError, ClientError


# -------------------- CONFIGURATION --------------------

SITES = {
    "store": "http://127.0.0.1/store",
    "restaurant": "http://127.0.0.1/restaurant",
    "clinic": "http://127.0.0.1/clinic",
}

FAILURE_THRESHOLD = 2
RECOVERY_THRESHOLD = 2

AWS_REGION = "ap-southeast-2"

SNS_TOPIC_ARN = (
    "arn:aws:sns:ap-southeast-2:761705104309:cloudguard-alerts"
)

CLOUDWATCH_NAMESPACE = "CloudGuard"
DYNAMODB_TABLE = "CloudGuardIncidents"

REPORT_DIR = Path("/opt/cloudguard/reports")
HEALTH_FILE = REPORT_DIR / "health_checks.csv"
INCIDENT_FILE = REPORT_DIR / "incidents.csv"
STATE_FILE = REPORT_DIR / "site_state.json"

HEALTH_FIELDS = [
    "timestamp_utc",
    "website",
    "url",
    "status_code",
    "response_ms",
    "healthy",
    "error",
]

INCIDENT_FIELDS = [
    "timestamp_utc",
    "website",
    "event",
    "status_code",
    "response_ms",
    "error",
]


# -------------------- AWS CLIENTS --------------------

sns = boto3.client("sns", region_name=AWS_REGION)

cloudwatch = boto3.client(
    "cloudwatch",
    region_name=AWS_REGION,
)

dynamodb = boto3.resource(
    "dynamodb",
    region_name=AWS_REGION,
)

incidents_table = dynamodb.Table(DYNAMODB_TABLE)


# -------------------- TIME --------------------

def now_utc():
    return datetime.now(timezone.utc).isoformat()


# -------------------- WEBSITE HEALTH CHECK --------------------

def check_website(name, url):
    start = time.perf_counter()
    status_code = None
    error = ""

    try:
        request = Request(
            url,
            headers={"User-Agent": "CloudGuard-Monitor/1.0"},
        )

        with urlopen(request, timeout=5) as response:
            status_code = response.status

    except HTTPError as exc:
        status_code = exc.code
        error = str(exc)

    except (URLError, TimeoutError, OSError) as exc:
        error = str(exc)

    response_ms = round(
        (time.perf_counter() - start) * 1000, 2
    )

    healthy = (
        status_code is not None
        and 200 <= status_code < 400
    )

    return {
        "timestamp_utc": now_utc(),
        "website": name,
        "url": url,
        "status_code": status_code or "",
        "response_ms": response_ms,
        "healthy": healthy,
        "error": error,
    }


# -------------------- CSV LOGGING --------------------

def append_csv(path, fields, row):
    new_file = not path.exists() or path.stat().st_size == 0

    with path.open("a", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields,
        )

        if new_file:
            writer.writeheader()

        writer.writerow(row)


# -------------------- CLOUDWATCH METRICS --------------------

def publish_cloudwatch_metrics(result):
    """Publish availability and response time for a website."""

    metric_data = [
        {
            "MetricName": "Availability",
            "Dimensions": [
                {
                    "Name": "Website",
                    "Value": result["website"],
                }
            ],
            "Value": 1 if result["healthy"] else 0,
            "Unit": "Count",
        },
        {
            "MetricName": "ResponseTime",
            "Dimensions": [
                {
                    "Name": "Website",
                    "Value": result["website"],
                }
            ],
            "Value": result["response_ms"],
            "Unit": "Milliseconds",
        },
    ]

    try:
        cloudwatch.put_metric_data(
            Namespace=CLOUDWATCH_NAMESPACE,
            MetricData=metric_data,
        )

        print(
            "CloudWatch metrics published: "
            f'{result["website"]}'
        )

    except (BotoCoreError, ClientError) as exc:
        print(f"CloudWatch publishing failed: {exc}")

    except Exception as exc:
        print(f"Unexpected CloudWatch error: {exc}")


# -------------------- SNS EMAIL ALERTS --------------------

def send_sns_alert(incident):
    """Send a DOWN or RECOVERED notification through SNS."""

    event = incident["event"]
    website = incident["website"]

    subject = f"CloudGuard {event}: {website}"

    message = (
        "CloudGuard Incident Notification\n\n"
        f"Event: {event}\n"
        f"Website: {website}\n"
        f'Timestamp (UTC): {incident["timestamp_utc"]}\n'
        f'HTTP status: {incident["status_code"] or "N/A"}\n'
        f'Response time: {incident["response_ms"]} ms\n'
        f'Error: {incident["error"] or "None"}\n'
    )

    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],
            Message=message,
        )

        print(
            "SNS alert accepted: "
            f'{response["MessageId"]}'
        )
        return True

    except (BotoCoreError, ClientError) as exc:
        print(f"SNS alert failed: {exc}")
        return False

    except Exception as exc:
        print(f"Unexpected SNS error: {exc}")
        return False


# -------------------- DYNAMODB INCIDENT STORAGE --------------------

def save_incident_to_dynamodb(incident):
    """
    Save a DOWN or RECOVERED incident to CloudGuardIncidents.

    The table's partition key is incident_id (String).
    Each transition receives a unique key based on its timestamp,
    website and event.
    """

    item = {
        "incident_id": (
            f'{incident["timestamp_utc"]}'
            f'#{incident["website"]}'
            f'#{incident["event"]}'
        ),
        "website": incident["website"],
        "event": incident["event"],
        "timestamp_utc": incident["timestamp_utc"],
        "status_code": str(incident["status_code"] or ""),
        "response_ms": str(incident["response_ms"]),
        "error": incident["error"] or "",
    }

    try:
        incidents_table.put_item(Item=item)

        print(
            "DynamoDB incident saved: "
            f'{incident["website"]} -> {incident["event"]}'
        )
        return True

    except (BotoCoreError, ClientError) as exc:
        print(f"DynamoDB write failed: {exc}")
        return False

    except Exception as exc:
        print(f"Unexpected DynamoDB error: {exc}")
        return False


# -------------------- STATE MANAGEMENT --------------------

def load_states():
    old_states = {}

    if STATE_FILE.exists():
        try:
            old_states = json.loads(
                STATE_FILE.read_text()
            )
        except (json.JSONDecodeError, OSError) as exc:
            print(f"Could not read previous state: {exc}")

    states = {}

    for name in SITES:
        old = old_states.get(name, "HEALTHY")

        if isinstance(old, str):
            states[name] = {
                "status": old,
                "failures": 0,
                "successes": 0,
            }
        else:
            states[name] = {
                "status": old.get("status", "HEALTHY"),
                "failures": int(old.get("failures", 0)),
                "successes": int(old.get("successes", 0)),
            }

    return states


# -------------------- MAIN MONITORING LOOP --------------------

def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    states = load_states()

    for name, url in SITES.items():
        result = check_website(name, url)
        state = states[name]
        previous_status = state["status"]

        # Record every health check in CSV.
        append_csv(
            HEALTH_FILE,
            HEALTH_FIELDS,
            result,
        )

        # Publish availability and latency metrics.
        publish_cloudwatch_metrics(result)

        # Update consecutive success/failure counters.
        if result["healthy"]:
            state["successes"] += 1
            state["failures"] = 0
        else:
            state["failures"] += 1
            state["successes"] = 0

        event = None

        # Transition to DOWN after consecutive failures.
        if (
            previous_status != "DOWN"
            and state["failures"] >= FAILURE_THRESHOLD
        ):
            state["status"] = "DOWN"
            event = "DOWN"

        # Transition to HEALTHY after consecutive successes.
        elif (
            previous_status == "DOWN"
            and state["successes"] >= RECOVERY_THRESHOLD
        ):
            state["status"] = "HEALTHY"
            event = "RECOVERED"

        if event:
            incident = {
                "timestamp_utc": result["timestamp_utc"],
                "website": name,
                "event": event,
                "status_code": result["status_code"],
                "response_ms": result["response_ms"],
                "error": result["error"],
            }

            # Preserve the local incident history.
            append_csv(
                INCIDENT_FILE,
                INCIDENT_FIELDS,
                incident,
            )

            print(f"INCIDENT: {name} -> {event}")

            # Save to DynamoDB independently of SNS delivery.
            save_incident_to_dynamodb(incident)

            # Send the email notification.
            send_sns_alert(incident)

        print(
            f'{name:12} | {state["status"]:7} | '
            f'HTTP {result["status_code"] or "N/A"} | '
            f'{result["response_ms"]} ms | '
            f'check={"HEALTHY" if result["healthy"] else "FAILED"} | '
            f'failures={state["failures"]} '
            f'successes={state["successes"]}'
        )

    # Save updated state after all websites have been checked.
    STATE_FILE.write_text(
        json.dumps(states, indent=2)
    )

    print(f"Health history: {HEALTH_FILE}")
    print(f"Incident history: {INCIDENT_FILE}")


if __name__ == "__main__":
    main()
