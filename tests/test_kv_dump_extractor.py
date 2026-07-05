"""
Tests for the alternating key/value dump parser in triage.raw_extractor.

Runnable two ways with no extra dependencies:
    python tests/test_kv_dump_extractor.py      # direct, prints PASS/FAIL
    pytest tests/test_kv_dump_extractor.py       # if pytest is installed

The fixture below is the real failing paste with all identifiers pseudonymized
(hostnames -> HOST-A, users -> USER-1, IDs -> *-REDACTED-*, IPs -> TEST-NET /
private ranges). Do not add other real dumps here.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from triage.raw_extractor import parse_raw_alert_to_field_inventory


KV_DUMP_FIXTURE = """\
Key
Value
cps.version
1.0.0
vendor
crowdstrike
#ecs.version
8.16.0
#event.dataset
falcon.insight
#event.kind
event
#event.module
falcon
#repo
xdr_indicatorsrepo
#repo.cid
CID-REDACTED-0001
#type
none
@id
EVT-REDACTED-0001
@ingesttimestamp
1783051968502
@timestamp
1783051410724
@timestamp.nanos
0
@timezone
Z
ngsiem.alert.id
CID-REDACTED-0001:ngsiem:CID-REDACTED-0001:IND-REDACTED-0001
ngsiem.detection.id
DET-REDACTED-0001
ngsiem.event.id
EVTID-REDACTED-0001
ngsiem.event.product
Falcon
ngsiem.event.subtype
result_event
ngsiem.event.type
ngsiem-rule-match-event
ngsiem.event.vendor
CrowdStrike
ngsiem.indicator.id
IND-REDACTED-0001
ngsiem.metadata
{"Metadata":null}
ngsiem.parent.indicator.id[0]
IND-REDACTED-0001
parser.version
1.2.0
vendor.# vendor
crowdstrike
vendor.@source
PlatformEvents
vendor. agent
203.0.113.66
vendor. authentication id
0
vendor. cap prm
2199023255551
vendor. change time
1778155115.557
vendor. config build
1007.8.0019102.15
vendor. config state hash
1461472139
vendor. description id
f_1529
vendor. file name
whoami
vendor. file path
/usr/bin/
vendor. local
10.0.0.1
vendor. pidnamespace id
4026531836
vendor. parent process id
1783051410517679454
vendor. process group id
1782947979534135509
vendor. root path
/
vendor. session process id
1782947979534135509
vendor. source process id
1783051410517679454
vendor. source thread id
0
vendor. technique id
T1033
vendor.aid
AGENT-REDACTED-0001
vendor.aip
203.0.113.66
vendor.cid
CID-REDACTED-0001
vendor.id
EVTID-REDACTED-0001
vendor.name
ProcessRollup2LinV14
vendor.user.name
USER-1
agent.id
AGENT-REDACTED-0001
event.action
ProcessRollup2
event.category[0]
process
event.type[0]
start
host.hostname
HOST-A
host.os.platform
Lin
process.command line
whoami
process.end
1783051410.523
process.entity id
1783051410519232682
process.executable
/usr/bin/whoami
process.group.id
0
process.hash.md5
60ced8e830339541fc5ae5301508a7fe
process.hash.sha1
0000000000000000000000000000000000000000
process.hash.sha256
32cbc89ed4c3b7d1fc39638d05a978485400110add622a3f2096f7fa528c69e7
process.parent.name
dash
process.pid
1105423
process.real group.id
0
process.real user.id
0
process.saved group.id
0
process.saved user.id
0
process.start
1783051410.519
process.tty
pts0
process.user.id
0
source.ip
10.0.0.1
threat.tactic.name[0]
Discovery
threat.technique.name[0]
System Owner/User Discovery
user.name
USER-1
"""


JSON_FIXTURE = (
    '{"AlertName": "Suspicious Process", "Severity": "High", '
    '"Entities": [{"Type": "host", "HostName": "HOST-A"}]}'
)


def test_kv_dump_parses_locally():
    result = parse_raw_alert_to_field_inventory(KV_DUMP_FIXTURE)
    fields = result["raw_fields"]

    assert result["input_type"] == "key_value_dump", result["input_type"]
    assert result["field_count"] >= 40, result["field_count"]

    # Keys preserved verbatim, including spaces and #/@ prefixes.
    assert fields["process.command line"] == "whoami"
    assert fields["#event.kind"] == "event"
    assert fields["@timezone"] == "Z"
    assert fields["vendor. file name"] == "whoami"

    # A value that is itself JSON stays a literal string (not exploded).
    assert fields["ngsiem.metadata"] == '{"Metadata":null}'

    # The Key/Value UI header was stripped, not turned into a field.
    assert "Key" not in fields and "Value" not in fields

    # Clean dump -> no "could not be paired" warning.
    assert result.get("warnings") == [], result.get("warnings")


def test_json_input_still_json():
    result = parse_raw_alert_to_field_inventory(JSON_FIXTURE)
    assert result["input_type"] == "json", result["input_type"]
    assert result["field_count"] >= 3, result["field_count"]


def _run():
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    if failures:
        print(f"\n{failures} test(s) failed")
        sys.exit(1)
    print("\nAll tests passed")


if __name__ == "__main__":
    _run()
