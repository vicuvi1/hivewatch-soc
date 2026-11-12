from hivewatch.sensors.fakeshell import FakeShell


def test_prompt_and_identity():
    sh = FakeShell("srv-prod-01", "root")
    assert sh.prompt == "root@srv-prod-01:~# "
    assert sh.run("whoami") == "root"
    assert "uid=0(root)" in sh.run("id")


def test_chained_commands_are_all_answered():
    sh = FakeShell()
    out = sh.run("uname -m; nproc && hostname")
    assert out.splitlines() == ["x86_64", "8", "srv-prod-01"]


def test_unknown_command_and_never_executes():
    sh = FakeShell()
    assert sh.run("definitely-not-a-cmd") == "-bash: definitely-not-a-cmd: command not found"
    # destructive commands are silently "accepted" and never executed
    assert sh.run("rm -rf /") == ""


def test_cd_changes_prompt():
    sh = FakeShell()
    sh.run("cd /tmp")
    assert sh.prompt.endswith(":/tmp# ")
