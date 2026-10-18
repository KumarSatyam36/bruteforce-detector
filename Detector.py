import re
import sys
from collections import defaultdict

THRESHOLD = 5  # failed attempts before flagging

PATTERN = re.compile(
    r"(?P<time>\w{3}\s+\d+\s[\d:]+).*Failed password for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)

def analyze(path):
    attempts = defaultdict(list)
    with open(path) as f:
        for line in f:
            m = PATTERN.search(line)
            if m:
                attempts[m["ip"]].append((m["time"], m["user"]))
    return attempts

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_auth.log"
    attempts = analyze(path)
    print(f"{'IP':<18}{'Attempts':<10}{'Users tried'}")
    for ip, events in sorted(attempts.items(), key=lambda x: -len(x[1])):
        if len(events) >= THRESHOLD:
            users = ", ".join(sorted({u for _, u in events}))
            print(f"{ip:<18}{len(events):<10}{users}  [ALERT]")

if __name__ == "__main__":
    main()
