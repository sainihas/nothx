"""Native daily scheduling and status coverage."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from nothx import scheduler


@pytest.mark.parametrize(
    ("system", "expected"),
    [("Darwin", "launchd"), ("Linux", "systemd"), ("Windows", "cron")],
)
def test_scheduler_type(system, expected, monkeypatch):
    monkeypatch.setattr(scheduler.platform, "system", lambda: system)
    assert scheduler.get_scheduler_type() == expected


def test_dispatch_and_unsupported_scheduler(monkeypatch):
    monkeypatch.setattr(scheduler, "get_scheduler_type", lambda: "launchd")
    monkeypatch.setattr(scheduler, "_install_launchd", lambda value: (True, value))
    assert scheduler.install_schedule("daily") == (True, "daily")

    monkeypatch.setattr(scheduler, "_uninstall_launchd", lambda: (True, "removed"))
    monkeypatch.setattr(scheduler, "_get_launchd_status", lambda: {"frequency": "daily"})
    assert scheduler.uninstall_schedule() == (True, "removed")
    assert scheduler.get_schedule_status() == {"frequency": "daily"}

    monkeypatch.setattr(scheduler, "get_scheduler_type", lambda: "cron")
    assert scheduler.install_schedule("daily")[0] is False
    assert scheduler.uninstall_schedule()[0] is False
    assert scheduler.get_schedule_status() is None


def test_launchd_daily_install_status_and_remove(tmp_path: Path, monkeypatch):
    plist = tmp_path / "Library" / "LaunchAgents" / "com.nothx.auto.plist"
    monkeypatch.setattr(scheduler, "get_launchd_path", lambda: plist)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(scheduler.subprocess, "run", run)

    success, message = scheduler._install_launchd("daily")
    status = scheduler._get_launchd_status()

    assert success is True and "daily" in message
    assert status is not None
    assert status["frequency"] == "daily"
    assert status["schedule"] == {"Hour": 9}
    assert any(call[:2] == ["launchctl", "load"] for call in calls)

    success, _ = scheduler._uninstall_launchd()
    assert success is True
    assert not plist.exists()
    assert scheduler._uninstall_launchd() == (True, "No schedule to remove")


def test_launchd_invalid_frequency_and_load_failure(tmp_path: Path, monkeypatch):
    plist = tmp_path / "job.plist"
    monkeypatch.setattr(scheduler, "get_launchd_path", lambda: plist)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    assert scheduler._install_launchd("hourly")[0] is False
    monkeypatch.setattr(
        scheduler.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1),
    )
    assert scheduler._install_launchd("daily") == (False, "Failed to load launchd job")


def test_systemd_daily_install_status_and_remove(tmp_path: Path, monkeypatch):
    service = tmp_path / "systemd" / "nothx.service"
    timer = tmp_path / "systemd" / "nothx.timer"
    monkeypatch.setattr(scheduler, "get_systemd_path", lambda: service)
    monkeypatch.setattr(scheduler, "get_systemd_timer_path", lambda: timer)
    monkeypatch.setattr(scheduler.subprocess, "run", lambda *args, **kwargs: None)

    success, message = scheduler._install_systemd("daily")
    status = scheduler._get_systemd_status()

    assert success is True and "daily" in message
    assert "nothx run --auto" in service.read_text()
    assert "OnCalendar=*-*-* 09:00:00" in timer.read_text()
    assert status is not None and status["frequency"] == "daily"

    success, _ = scheduler._uninstall_systemd()
    assert success is True
    assert not service.exists() and not timer.exists()


@pytest.mark.parametrize(
    ("frequency", "calendar"),
    [("monthly", "*-*-01 09:00:00"), ("weekly", "Sun 09:00:00")],
)
def test_systemd_other_supported_frequencies(frequency, calendar, tmp_path: Path, monkeypatch):
    service = tmp_path / frequency / "nothx.service"
    timer = tmp_path / frequency / "nothx.timer"
    monkeypatch.setattr(scheduler, "get_systemd_path", lambda: service)
    monkeypatch.setattr(scheduler, "get_systemd_timer_path", lambda: timer)
    monkeypatch.setattr(scheduler.subprocess, "run", lambda *args, **kwargs: None)

    assert scheduler._install_systemd(frequency)[0] is True
    assert f"OnCalendar={calendar}" in timer.read_text()
    assert scheduler._get_systemd_status()["frequency"] == frequency


def test_systemd_invalid_frequency(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(scheduler, "get_systemd_path", lambda: tmp_path / "service")
    monkeypatch.setattr(scheduler, "get_systemd_timer_path", lambda: tmp_path / "timer")
    assert scheduler._install_systemd("hourly")[0] is False
