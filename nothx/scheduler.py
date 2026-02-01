"""Scheduler management for nothx (launchd on macOS, systemd on Linux)."""

import platform
import plistlib
import subprocess
import sys
from pathlib import Path


def get_scheduler_type() -> str:
    """Get the appropriate scheduler for this system."""
    system = platform.system()
    if system == "Darwin":
        return "launchd"
    elif system == "Linux":
        return "systemd"
    else:
        return "cron"


def get_launchd_path() -> Path:
    """Get the path to the launchd plist file."""
    return Path.home() / "Library" / "LaunchAgents" / "com.nothx.auto.plist"


def get_systemd_path() -> Path:
    """Get the path to the systemd service file."""
    return Path.home() / ".config" / "systemd" / "user" / "nothx.service"


def get_systemd_timer_path() -> Path:
    """Get the path to the systemd timer file."""
    return Path.home() / ".config" / "systemd" / "user" / "nothx.timer"


def install_schedule(frequency: str = "monthly") -> tuple[bool, str]:
    """
    Install automatic scheduling.

    Args:
        frequency: "monthly", "weekly", or "daily"

    Returns:
        Tuple of (success, message)
    """
    scheduler = get_scheduler_type()

    if scheduler == "launchd":
        return _install_launchd(frequency)
    elif scheduler == "systemd":
        return _install_systemd(frequency)
    else:
        return False, f"Unsupported scheduler: {scheduler}. Please set up cron manually."


def uninstall_schedule() -> tuple[bool, str]:
    """Remove automatic scheduling."""
    scheduler = get_scheduler_type()

    if scheduler == "launchd":
        return _uninstall_launchd()
    elif scheduler == "systemd":
        return _uninstall_systemd()
    else:
        return False, "Unsupported scheduler"


def get_schedule_status() -> dict | None:
    """Get current schedule status."""
    scheduler = get_scheduler_type()

    if scheduler == "launchd":
        return _get_launchd_status()
    elif scheduler == "systemd":
        return _get_systemd_status()
    return None


def _install_launchd(frequency: str) -> tuple[bool, str]:
    """Install launchd schedule on macOS."""
    plist_path = get_launchd_path()
    plist_path.parent.mkdir(parents=True, exist_ok=True)

    # Get the nothx command path
    nothx_path = sys.executable
    nothx_args = [nothx_path, "-m", "nothx", "run", "--auto"]

    # Build schedule based on frequency
    if frequency == "monthly":
        schedule = {"Day": 1, "Hour": 9}  # 1st of month at 9am
    elif frequency == "weekly":
        schedule = {"Weekday": 0, "Hour": 9}  # Sunday at 9am
    elif frequency == "daily":
        schedule = {"Hour": 9}  # Every day at 9am
    else:
        return False, f"Invalid frequency: {frequency}"

    plist = {
        "Label": "com.nothx.auto",
        "ProgramArguments": nothx_args,
        "StartCalendarInterval": schedule,
        "StandardOutPath": str(Path.home() / ".nothx" / "logs" / "stdout.log"),
        "StandardErrorPath": str(Path.home() / ".nothx" / "logs" / "stderr.log"),
        "RunAtLoad": False,
    }

    # Create logs directory
    (Path.home() / ".nothx" / "logs").mkdir(parents=True, exist_ok=True)

    try:
        # Unload existing if present
        if plist_path.exists():
            subprocess.run(
                ["launchctl", "unload", str(plist_path)], capture_output=True, check=False
            )

        # Write plist
        with open(plist_path, "wb") as f:
            plistlib.dump(plist, f)

        # Load the new plist
        result = subprocess.run(
            ["launchctl", "load", str(plist_path)], capture_output=True, check=False
        )
        if result.returncode != 0:
            return False, "Failed to load launchd job"

        return True, f"Scheduled {frequency} runs via launchd"

    except Exception as e:
        return False, str(e)


def _uninstall_launchd() -> tuple[bool, str]:
    """Uninstall launchd schedule."""
    plist_path = get_launchd_path()

    if not plist_path.exists():
        return True, "No schedule to remove"

    try:
        subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True, check=False)
        plist_path.unlink()
        return True, "Schedule removed"
    except Exception as e:
        return False, str(e)


def _get_launchd_status() -> dict | None:
    """Get launchd schedule status."""
    plist_path = get_launchd_path()

    if not plist_path.exists():
        return None

    try:
        with open(plist_path, "rb") as f:
            plist = plistlib.load(f)

        schedule = plist.get("StartCalendarInterval", {})

        # Determine frequency
        if "Day" in schedule:
            frequency = "monthly"
        elif "Weekday" in schedule:
            frequency = "weekly"
        else:
            frequency = "daily"

        return {
            "type": "launchd",
            "frequency": frequency,
            "schedule": schedule,
            "path": str(plist_path),
        }
    except Exception:
        return None


def _install_systemd(frequency: str) -> tuple[bool, str]:
    """Install systemd schedule on Linux."""
    service_path = get_systemd_path()
    timer_path = get_systemd_timer_path()

    service_path.parent.mkdir(parents=True, exist_ok=True)

    nothx_path = sys.executable

    # Create service file
    service_content = f"""[Unit]
Description=nothx email unsubscribe automation

[Service]
Type=oneshot
ExecStart={nothx_path} -m nothx run --auto
"""

    # Create timer file
    if frequency == "monthly":
        on_calendar = "*-*-01 09:00:00"
    elif frequency == "weekly":
        on_calendar = "Sun 09:00:00"
    elif frequency == "daily":
        on_calendar = "*-*-* 09:00:00"
    else:
        return False, f"Invalid frequency: {frequency}"

    timer_content = f"""[Unit]
Description=nothx scheduled run

[Timer]
OnCalendar={on_calendar}
Persistent=true

[Install]
WantedBy=timers.target
"""

    try:
        # Write files
        with open(service_path, "w") as f:
            f.write(service_content)

        with open(timer_path, "w") as f:
            f.write(timer_content)

        # Reload and enable
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, check=False)
        subprocess.run(
            ["systemctl", "--user", "enable", "nothx.timer"], capture_output=True, check=False
        )
        subprocess.run(
            ["systemctl", "--user", "start", "nothx.timer"], capture_output=True, check=False
        )

        return True, f"Scheduled {frequency} runs via systemd"

    except Exception as e:
        return False, str(e)


def _uninstall_systemd() -> tuple[bool, str]:
    """Uninstall systemd schedule."""
    try:
        subprocess.run(
            ["systemctl", "--user", "stop", "nothx.timer"], capture_output=True, check=False
        )
        subprocess.run(
            ["systemctl", "--user", "disable", "nothx.timer"], capture_output=True, check=False
        )

        service_path = get_systemd_path()
        timer_path = get_systemd_timer_path()

        if service_path.exists():
            service_path.unlink()
        if timer_path.exists():
            timer_path.unlink()

        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, check=False)

        return True, "Schedule removed"
    except Exception as e:
        return False, str(e)


def _get_systemd_status() -> dict | None:
    """Get systemd schedule status."""
    timer_path = get_systemd_timer_path()

    if not timer_path.exists():
        return None

    try:
        with open(timer_path) as f:
            content = f.read()

        # Parse OnCalendar
        for line in content.split("\n"):
            if line.startswith("OnCalendar="):
                on_calendar = line.split("=")[1]

                if "*-*-01" in on_calendar:
                    frequency = "monthly"
                elif "Sun" in on_calendar:
                    frequency = "weekly"
                else:
                    frequency = "daily"

                return {
                    "type": "systemd",
                    "frequency": frequency,
                    "on_calendar": on_calendar,
                    "path": str(timer_path),
                }
    except Exception:
        pass

    return None
