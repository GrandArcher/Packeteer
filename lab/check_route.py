#!/usr/bin/env python3
"""Check Packeteer's injected route in `show bgp ipv4 unicast json`.

Usage:
  check_route.py present < table.json
  check_route.py absent  < table.json
  check_route.py --self-test

present: a path for 198.51.100.0/24 has next hop 192.0.2.2, local-pref 250,
community 64512:666, and no-export.
absent: no path carries community 64512:666 (the router's own copy of the
prefix, with next hop 192.0.2.1 and no Packeteer community, may remain).

Keep the constants in sync with lab/packeteer.yaml.
"""

import json
import sys

PREFIX = "198.51.100.0/24"
NEXTHOP = "192.0.2.2"
COMMUNITY = "64512:666"
LOCAL_PREF = 250


def load(text):
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


def walk(obj):
    if isinstance(obj, dict):
        if any(k in obj for k in ("nexthops", "community", "locPrf", "localPref")):
            yield obj
        for v in obj.values():
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)


def nexthops(path):
    out = []
    for key in ("nexthops", "nextHops", "nexthop"):
        val = path.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict) and isinstance(item.get("ip"), str):
                    out.append(item["ip"])
                elif isinstance(item, str):
                    out.append(item)
        elif isinstance(val, str):
            out.append(val)
    return out


def local_pref(path):
    for key in ("locPrf", "localPref", "localpref", "localPreference"):
        if key in path and path[key] is not None:
            try:
                return int(path[key])
            except (TypeError, ValueError):
                return None
    return None


def communities(path):
    found = []
    for key in ("community", "communities"):
        c = path.get(key)
        if isinstance(c, dict):
            if isinstance(c.get("list"), list):
                found.extend(str(x) for x in c["list"])
            if isinstance(c.get("string"), str):
                found.extend(c["string"].split())
        elif isinstance(c, list):
            found.extend(str(x) for x in c)
        elif isinstance(c, str):
            found.extend(c.split())
    return [x.lower() for x in found]


def has_packeteer(path):
    return COMMUNITY in communities(path)


def is_injected(path):
    comms = communities(path)
    return (
        NEXTHOP in nexthops(path)
        and local_pref(path) == LOCAL_PREF
        and COMMUNITY in comms
        and ("no-export" in comms or "no_export" in comms)
    )


def main(argv):
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) != 2 or argv[1] not in ("present", "absent"):
        print("usage: check_route.py present|absent", file=sys.stderr)
        return 2
    doc = load(sys.stdin.read())
    paths = list(walk(doc)) if doc is not None else []
    injected = [p for p in paths if is_injected(p)]
    tagged = [p for p in paths if has_packeteer(p)]
    if argv[1] == "present":
        if injected:
            return 0
        print("injected route not found in bgp table", file=sys.stderr)
        return 1
    if tagged:
        print("packeteer community still present", file=sys.stderr)
        return 1
    return 0


def self_test():
    present = {
        "routes": {
            PREFIX: [
                {
                    "locPrf": LOCAL_PREF,
                    "nexthops": [{"ip": NEXTHOP}],
                    "community": {"list": [COMMUNITY, "no-export"]},
                },
                {"locPrf": 100, "nexthops": [{"ip": "192.0.2.1"}]},
            ]
        }
    }
    absent = {"routes": {PREFIX: [{"locPrf": 100, "nexthops": [{"ip": "192.0.2.1"}]}]}}
    if main_on(present, "present") != 0 or main_on(absent, "absent") != 0:
        return 1
    if main_on(absent, "present") == 0 or main_on(present, "absent") == 0:
        return 1
    return 0


def main_on(doc, mode):
    raw = json.dumps(doc)
    old = sys.stdin
    sys.stdin = __import__("io").StringIO(raw)
    try:
        return main([sys.argv[0], mode])
    finally:
        sys.stdin = old


if __name__ == "__main__":
    sys.exit(main(sys.argv))
