# SSH Brute-Force Detector

A Python tool that parses Linux `auth.log` files and flags source IPs
with repeated failed SSH login attempts, simulating a basic SOC
detection rule used to catch brute-force attacks.

## Features
- Parses SSH auth logs using regex
- Groups failed login attempts by source IP
- Flags IPs that cross a configurable threshold (default: 5 attempts)
- Lists which usernames were targeted per IP

## Usage
```
python3 detector.py sample_auth.log
```

## Example Output
```
IP                Attempts  Users tried
203.0.113.45      7         admin, oracle, root, test, ubuntu  [ALERT]
198.51.100.23     5         guest, pi, root  [ALERT]
```

## Detection Logic
The script matches "Failed password" entries, extracts the source IP,
username, and timestamp, then aggregates attempts per IP. Any IP
meeting or exceeding the threshold is flagged as a likely brute-force
source.

## MITRE ATT&CK Mapping
T1110 - Brute Force

 Equivalent Splunk Query
```
index=auth "Failed password" | rex "from (?<src_ip>[\d.]+)" | stats count by src_ip | where count >= 5
```

## Future Improvements
- Time-window based detection (e.g. 5 attempts within 60 seconds)
- GeoIP lookup for source IPs
- Email/Slack alerting integration
