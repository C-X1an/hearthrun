"""Pure observation validation; these checks alone establish no native result."""
import errno
import re

TRANSPORTS = ("tcp", "udp", "unix", "dns")
# A fixed A/IN question for the reserved .invalid name; sent only to our UDP
# receiver on 127.0.0.1, never through libc/system DNS or a real resolver.
DNS_CONTROL = b"MC\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09hearthrun\x07invalid\x00\x00\x01\x00\x01"
CONTROLS = {"tcp": b"hearthrun-control-tcp\n", "udp": b"hearthrun-control-udp\n",
            "unix": b"hearthrun-control-unix\n", "dns": DNS_CONTROL}
NUMBER = r"(?:0|[1-9][0-9]*|-1)"
OPTIONAL = r"(?:NA|" + NUMBER + r")"
LINE = re.compile(
    r"(tcp|udp|unix|dns) socket=(" + NUMBER + r") socket_errno=(" + NUMBER +
    r") connect=(" + OPTIONAL + r") connect_errno=(" + OPTIONAL +
    r") send=(" + OPTIONAL + r") send_errno=(" + OPTIONAL + r")\n")


def validate_controls(records, phase):
    if set(records) != set(TRANSPORTS):
        raise ValueError("incomplete control transports")
    for name in TRANSPORTS:
        expected = {"accepts": int(name in {"tcp", "unix"}), "messages": [CONTROLS[name].hex()]}
        if records[name] != expected:
            raise ValueError(f"{name}: {phase} control not observed exactly once")


def validate(data):
    if set(data) != {"guest", "listeners"} or set(data["guest"]) != set(TRANSPORTS):
        raise ValueError("incomplete network observation")
    if set(data["listeners"]) != {"before", "guest", "after"}:
        raise ValueError("incomplete listener phases")
    for phase in ("before", "after"):
        validate_controls(data["listeners"][phase], phase)
    for name in TRANSPORTS:
        expected = {"socket_result": -1, "socket_errno": errno.EPERM,
                    "connect_result": None, "connect_errno": None,
                    "send_result": None, "send_errno": None}
        if data["guest"][name] != expected:
            raise ValueError(f"{name}: socket creation was not actually refused with EPERM")
        for phase in ("before", "guest", "after"):
            if set(data["listeners"][phase]) != set(TRANSPORTS):
                raise ValueError("incomplete listener transports")
            expected_accepts = int(phase != "guest" and name in {"tcp", "unix"})
            expected_messages = [] if phase == "guest" else [CONTROLS[name].hex()]
            observed = data["listeners"][phase][name]
            if observed != {"accepts": expected_accepts, "messages": expected_messages}:
                kind = "guest connection/message observed" if phase == "guest" else "control not observed exactly once"
                raise ValueError(f"{name}: {phase} {kind}")


def parse_guest(data):
    if not isinstance(data, bytes) or len(data) > 4096:
        raise ValueError("guest observations exceed bound or are not bytes")
    try:
        lines = data.decode("ascii").splitlines(keepends=True)
    except UnicodeError as error:
        raise ValueError("guest observations are not ASCII") from error
    if len(lines) != len(TRANSPORTS):
        raise ValueError("missing or surplus guest observations")
    result = {}
    keys = ("socket_result", "socket_errno", "connect_result", "connect_errno", "send_result", "send_errno")
    for name, line in zip(TRANSPORTS, lines):
        match = LINE.fullmatch(line)
        if match is None or match[1] != name:
            raise ValueError("malformed or reordered guest observation")
        result[name] = {key: None if value == "NA" else int(value)
                        for key, value in zip(keys, match.groups()[1:])}
    return result
