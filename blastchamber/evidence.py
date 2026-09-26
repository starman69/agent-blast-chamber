"""evidence — attach real CloudTrail events to a live report.

A live run records every call it made (report["live"]["calls"]). CloudTrail delivers the
matching events to the lab's CloudWatch Logs group a few minutes later; this module queries
that group with Logs Insights, matches each recorded call to its event, and appends the
event ids to the stage evidence. The report then cites the receipts instead of asserting.

The parsing and matching functions are pure so they can be tested without AWS.
"""
from __future__ import annotations

import datetime as _dt
import time

CONTAINMENT_POLICY = "blast-chamber-containment"

# CloudTrail eventName -> the stage it is evidence for.
STAGE_BY_EVENT = {
    "ApplyGuardrail": "prompt-injection",
    "GetSecretValue": "decoy-credentials",
    "GetCallerIdentity": "aws-identity",
    "GetParameter": "aws-identity",
    "PutRolePolicy": "aws-identity",      # the containment Lambda revoking the session
    "GetObject": "decoy-resource-access",
    "Scan": "decoy-resource-access",
}

# Calls made by the gateway may not all be in CloudTrail; only the agent's are required.
REQUIRED_IDENTITY = "agent"

_FIELDS = ("@timestamp", "eventTime", "eventID", "eventName", "eventSource", "errorCode",
           "userIdentity.arn", "requestParameters.policyName")


def build_query(session_name: str) -> str:
    return (
        f"fields {', '.join(_FIELDS)}"
        f" | filter userIdentity.arn like /{session_name}/"
        f" or (eventName = 'PutRolePolicy' and requestParameters.policyName = '{CONTAINMENT_POLICY}')"
        f" or eventName = 'ApplyGuardrail'"
        " | sort eventTime asc | limit 500"
    )


def parse_rows(rows: list[list[dict]]) -> list[dict]:
    """Logs Insights result rows -> flat dicts keyed by field name."""
    return [{c["field"]: c["value"] for c in row if not c["field"].startswith("@ptr")}
            for row in rows]


def who(event: dict, session_name: str) -> str:
    arn = event.get("userIdentity.arn", "")
    if session_name in arn:
        return "agent"
    # Only the Lambda *writing* the revoke policy is containment. deploy.sh/teardown.sh
    # deleting it (DeleteRolePolicy) carries the same policy name but is lab housekeeping.
    if (event.get("eventName") == "PutRolePolicy"
            and event.get("requestParameters.policyName") == CONTAINMENT_POLICY):
        return "containment"
    return "gateway"


def result_of(event: dict) -> str:
    return event.get("errorCode") or "ALLOWED"


def match_calls(calls: list[dict], events: list[dict], session_name: str):
    """Pair each recorded call with an unused event of the same API and result.

    Returns (matched: list[(call, event)], missing: list[call]).
    """
    used: set[int] = set()
    matched, missing = [], []
    for call in calls:
        want_denied = call["result"] != "ALLOWED"
        for i, ev in enumerate(events):
            if i in used or ev.get("eventName") != call["api"]:
                continue
            if who(ev, session_name) != call["identity"]:
                continue
            if (result_of(ev) != "ALLOWED") != want_denied:
                continue
            used.add(i)
            matched.append((call, ev))
            break
        else:
            missing.append(call)
    return matched, missing


def evidence_line(event: dict, session_name: str) -> str:
    return (f"cloudtrail {event.get('eventTime', '?')} {event.get('eventName')} "
            f"{result_of(event)} as {who(event, session_name)} event={event.get('eventID')}")


def containment_events(report: dict, events: list[dict]) -> list[dict]:
    """The containment write that belongs to THIS run, if the profile has containment.

    The Lambda's PutRolePolicy carries no agent session, and the search window runs past the
    run, so without this a later run3 revocation would be credited to an earlier run.
    """
    if not report.get("controls", {}).get("containment"):
        return []
    start = report["live"]["window_start"].replace("+00:00", "Z")
    mine = [ev for ev in events if who(ev, report["live"]["session_name"]) == "containment"
            and ev.get("eventTime", "") >= start]
    return mine[:1]


def attach(report: dict, events: list[dict]) -> dict:
    """Append CloudTrail evidence lines to each stage and summarise the match."""
    live = report["live"]
    session = live["session_name"]
    matched, missing = match_calls(live["calls"], events, session)
    contained = containment_events(report, events)

    by_stage: dict[str, list[str]] = {}
    for _, ev in matched:
        by_stage.setdefault(STAGE_BY_EVENT.get(ev["eventName"], "?"), []).append(
            evidence_line(ev, session))
    # Containment isn't a call the harness made; attach this run's revocation, if any.
    for ev in contained:
        by_stage.setdefault("aws-identity", []).append(evidence_line(ev, session))

    for st in report["stages"]:
        st["evidence"] = [e for e in st["evidence"] if not e.startswith("cloudtrail ")]
        st["evidence"].extend(by_stage.get(st["name"], []))

    report["cloudtrail"] = {
        "log_group": live["log_group"],
        "query": build_query(session),
        "calls_recorded": len(live["calls"]),
        "calls_matched": len(matched),
        "missing": [f"{c['api']} {c['result']} as {c['identity']}"
                    for c in missing if c["identity"] == REQUIRED_IDENTITY],
        # Bedrock doesn't record ApplyGuardrail as a management event; its API response is
        # already in the stage evidence.
        "gateway_not_in_cloudtrail": [c["api"] for c in missing if c["identity"] != REQUIRED_IDENTITY],
        "containment_events": len(contained),
    }
    return report


def _still_missing_required(report: dict, events: list[dict]) -> int:
    live = report["live"]
    _, missing = match_calls(live["calls"], events, live["session_name"])
    return sum(1 for c in missing if c["identity"] == REQUIRED_IDENTITY)


def query_events(logs, report: dict) -> list[dict]:
    """Run the Logs Insights query over the run's time window."""
    live = report["live"]
    start = _dt.datetime.fromisoformat(live["window_start"]) - _dt.timedelta(minutes=2)
    end = _dt.datetime.fromisoformat(live["window_end"]) + _dt.timedelta(minutes=20)
    end = min(end, _dt.datetime.now(_dt.timezone.utc))
    qid = logs.start_query(
        logGroupName=live["log_group"],
        startTime=int(start.timestamp()), endTime=int(end.timestamp()),
        queryString=build_query(live["session_name"]), limit=500,
    )["queryId"]
    while True:
        res = logs.get_query_results(queryId=qid)
        if res["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
        time.sleep(2)
    if res["status"] != "Complete":
        raise RuntimeError(f"Logs Insights query {res['status']}")
    return parse_rows(res["results"])


def collect(logs, report: dict, wait_seconds: int = 0, log=print) -> tuple[dict, list[dict]]:
    """Query (and optionally wait) until every agent call has its CloudTrail event."""
    t0 = time.monotonic()
    while True:
        events = query_events(logs, report)
        left = _still_missing_required(report, events)
        if left == 0 or time.monotonic() - t0 >= wait_seconds:
            break
        log(f"  {left} agent call(s) not in CloudTrail yet "
            f"({int(time.monotonic() - t0)}s) - delivery takes a few minutes ...")
        time.sleep(30)
    return attach(report, events), events
