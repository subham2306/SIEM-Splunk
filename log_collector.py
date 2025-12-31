import time
import re

AUTH_LOG = "/var/log/auth.log"
SOC_LOG = "/var/log/soc_events.log"

failed_regex = re.compile(
    r"Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def follow(file):
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line

with open(AUTH_LOG, "r") as auth:
    for line in follow(auth):
        match = failed_regex.search(line)
        if match:
            user = match.group("user")
            ip = match.group("ip")

            event = (
                f"attack_type=SSH_Brute_Force "
                f"attacker_ip={ip} "
                f"user={user}\n"
            )

            with open(SOC_LOG, "a") as soc:
                soc.write(event)

            print("[+] Logged:", event.strip())

