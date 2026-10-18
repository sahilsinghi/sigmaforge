"""Generate a deterministic benign baseline: a week of normal office telemetry.

A rule that never fires in tests is not necessarily a good rule; you only
learn how noisy it is by replaying it against a large amount of *normal*
activity. The best baseline is a real Windows VM with Sysmon used for a few
days (see ``scripts/Export-SysmonBaseline.ps1``). This generator is the
stand-in that keeps CI hermetic: a seeded simulation of a small company -
nine workstations, a file server, a domain controller and an app server -
with the activity that makes real detections noisy:

* software that legitimately writes Run keys under AppData (OneDrive, Teams,
  Slack, Discord, Spotify, Zoom, GitHub Desktop)
* SCCM running encoded PowerShell, an IT admin running whoami /all, PsExec
  and adding a new hire to local Administrators
* a finance macro that shells out from Excel
* a developer who opens an ngrok link now and then
* users mistyping passwords, and a service account with a stale password
  that fails every fifteen minutes
* Defender, svchost and Task Manager opening lsass

The output is byte-for-byte reproducible for a given seed, so CI can check
the corpus hash and a changed baseline shows up in review.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import random
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

GENERATOR_VERSION = 1
SYSMON = "Microsoft-Windows-Sysmon/Operational"
DOMAIN = "corp.local"

PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
EXPLORER = "C:\\Windows\\explorer.exe"
SVCHOST = "C:\\Windows\\System32\\svchost.exe"
SERVICES = "C:\\Windows\\System32\\services.exe"
OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\"
CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
LSASS = "C:\\Windows\\system32\\lsass.exe"
DEFENDER = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe"

COMMON_DOMAINS = [
    "login.microsoftonline.com", "outlook.office365.com", "graph.microsoft.com",
    "teams.microsoft.com", "www.google.com", "fonts.gstatic.com", "github.com",
    "api.github.com", "slack.com", "wss-primary.slack.com", "zoom.us",
    "update.googleapis.com", "settings-win.data.microsoft.com", "ctldl.windowsupdate.com",
    "www.bing.com", "intranet.corp.local", "fileserver.corp.local", "wpad.corp.local",
    "cdn.jsdelivr.net", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
    "stackoverflow.com", "docs.python.org", "www.linkedin.com", "news.ycombinator.com",
]


@dataclass(frozen=True)
class Host:
    name: str
    ip: str
    user: str | None
    sid: int
    roles: frozenset[str]

    @property
    def fqdn(self) -> str:
        return f"{self.name}.{DOMAIN}"

    @property
    def home(self) -> str:
        return f"C:\\Users\\{self.user}"


HOSTS = [
    Host("WS-001", "10.10.20.11", "alice", 1101, frozenset({"office", "spotify"})),
    Host("WS-002", "10.10.20.12", "bob", 1102, frozenset({"office", "zoom"})),
    Host("WS-003", "10.10.20.13", "carol", 1103, frozenset({"office", "finance"})),
    Host("WS-004", "10.10.20.14", "dave", 1104, frozenset({"office", "developer", "slack"})),
    Host("WS-005", "10.10.20.15", "erin", 1105, frozenset({"office", "spotify", "zoom"})),
    Host("WS-006", "10.10.20.16", "frank", 1106, frozenset({"office"})),
    Host("WS-007", "10.10.20.17", "grace", 1107, frozenset({"office", "developer", "discord", "slack"})),
    Host("WS-008", "10.10.20.18", "heidi", 1108, frozenset({"office", "zoom"})),
    Host("WS-009", "10.10.20.19", "it.admin", 1109, frozenset({"office", "itadmin", "slack"})),
    Host("SRV-FILE01", "10.10.10.21", None, 0, frozenset({"server", "fileserver"})),
    Host("SRV-DC01", "10.10.10.10", None, 0, frozenset({"server", "dc"})),
    Host("SRV-APP01", "10.10.30.5", None, 0, frozenset({"server", "app"})),
]


@dataclass
class CorpusInfo:
    path: Path
    hosts: int
    days: int
    start: str
    end: str
    seed: int
    events: int
    sha256: str

    def to_json(self) -> dict[str, Any]:
        return {
            "generator": "sigmaforge.baseline",
            "generator_version": GENERATOR_VERSION,
            "file": self.path.name,
            "hosts": self.hosts,
            "days": self.days,
            "start": self.start,
            "end": self.end,
            "seed": self.seed,
            "events": self.events,
            "sha256": self.sha256,
        }


class _Day:
    """Collects one host-day of events with timestamps inside that day."""

    def __init__(self, rng: random.Random, host: Host, day: date):
        self.rng = rng
        self.host = host
        self.day = day
        self.events: list[dict[str, Any]] = []
        self.pid = rng.randint(2000, 9000)

    # -- time helpers ----------------------------------------------------
    def at(self, hour: float, jitter_min: float = 20.0) -> datetime:
        minutes = hour * 60 + self.rng.uniform(-jitter_min, jitter_min)
        minutes = min(max(minutes, 0.0), 24 * 60 - 0.01)
        base = datetime(self.day.year, self.day.month, self.day.day, tzinfo=timezone.utc)
        return base + timedelta(minutes=minutes, milliseconds=self.rng.randint(0, 999))

    def work_time(self) -> datetime:
        return self.at(self.rng.uniform(8.5, 17.5), 0)

    # -- event builders --------------------------------------------------
    def _base(self, when: datetime, channel: str, event_id: int) -> dict[str, Any]:
        return {
            "EventID": event_id,
            "Channel": channel,
            "Computer": self.host.fqdn,
            "@timestamp": when.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        }

    @property
    def user(self) -> str:
        return f"CORP\\{self.host.user}" if self.host.user else "NT AUTHORITY\\SYSTEM"

    def proc(self, when, image, cmd, parent=EXPLORER, user=None, ofn=None, desc="", integrity="Medium"):
        self.pid += self.rng.randint(4, 64)
        ev = self._base(when, SYSMON, 1)
        ev.update(
            Image=image,
            CommandLine=cmd,
            ParentImage=parent,
            User=user or self.user,
            OriginalFileName=ofn or image.rsplit("\\", 1)[-1],
            Description=desc,
            IntegrityLevel=integrity,
            ProcessId=self.pid,
            CurrentDirectory=(self.host.home + "\\") if self.host.user else "C:\\Windows\\system32\\",
        )
        self.events.append(ev)

    def reg(self, when, image, key, details):
        ev = self._base(when, SYSMON, 13)
        ev.update(EventType="SetValue", Image=image, TargetObject=key, Details=details, User=self.user)
        self.events.append(ev)

    def access(self, when, source, target, granted):
        ev = self._base(when, SYSMON, 10)
        ev.update(SourceImage=source, TargetImage=target, GrantedAccess=granted,
                  SourceUser="NT AUTHORITY\\SYSTEM", TargetUser="NT AUTHORITY\\SYSTEM")
        self.events.append(ev)

    def pipe(self, when, image, name):
        ev = self._base(when, SYSMON, 17)
        ev.update(EventType="CreatePipe", Image=image, PipeName=name)
        self.events.append(ev)

    def dns(self, when, image, query):
        ev = self._base(when, SYSMON, 22)
        ev.update(Image=image, QueryName=query, QueryStatus="0")
        self.events.append(ev)

    def net(self, when, image, dst_ip, dst_port, hostname=""):
        ev = self._base(when, SYSMON, 3)
        ev.update(Image=image, Protocol="tcp", Initiated="true", SourceIp=self.host.ip,
                  DestinationIp=dst_ip, DestinationPort=dst_port, DestinationHostname=hostname)
        self.events.append(ev)

    def security(self, when, event_id, **fields):
        ev = self._base(when, "Security", event_id)
        ev.update(fields)
        self.events.append(ev)

    def system(self, when, event_id, **fields):
        ev = self._base(when, "System", event_id)
        ev.update(fields)
        self.events.append(ev)


def _hkcu_run(host: Host) -> str:
    return f"HKU\\S-1-5-21-1111111111-2222222222-3333333333-{host.sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"


# ---------------------------------------------------------------------------
# Activity models
# ---------------------------------------------------------------------------

def _system_background(d: _Day, workday: bool) -> None:
    rng = d.rng
    for hour in range(24):
        when = d.at(hour + 0.5, 25)
        d.access(when, DEFENDER, LSASS, "0x1410")
        d.access(d.at(hour + 0.2, 10), SVCHOST, LSASS, rng.choice(["0x1000", "0x1410", "0x3000"]))
        d.proc(when, "C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe", parent=SVCHOST, user="NT AUTHORITY\\SYSTEM")
        if rng.random() < 0.6:
            d.proc(d.at(hour + 0.7, 20), "C:\\Windows\\System32\\backgroundTaskHost.exe",
                   '"backgroundTaskHost.exe" -ServerName:BackgroundTaskHost.WebAccountBackgroundTask',
                   parent=SVCHOST)
        if rng.random() < 0.4:
            d.proc(d.at(hour + 0.3, 20), "C:\\Windows\\System32\\SearchProtocolHost.exe",
                   '"C:\\Windows\\system32\\SearchProtocolHost.exe" Global\\UsGthrFltPipeMssGthrPipe1_ Global\\UsGthrCtrlFltPipeMssGthrPipe1 1 -2147483646',
                   parent="C:\\Windows\\System32\\SearchIndexer.exe", user="NT AUTHORITY\\SYSTEM")
        for _ in range(rng.randint(2, 6)):
            d.dns(d.at(hour + 0.5, 30), SVCHOST, rng.choice(COMMON_DOMAINS[:8] + ["ctldl.windowsupdate.com", "settings-win.data.microsoft.com"]))
        d.pipe(d.at(hour + 0.4, 25), SVCHOST, f"\\Winsock2\\CatalogChangeListener-{rng.randint(100, 999):x}-0")
    # updaters run a few times a day
    for hour in (2, 10, 15, 21):
        when = d.at(hour, 30)
        d.proc(when, "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
               '"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe" /ua /installsource scheduler',
               parent=SVCHOST, user="NT AUTHORITY\\SYSTEM")
        d.proc(d.at(hour, 30), "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe",
               '"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe" /ua /installsource scheduler',
               parent=SVCHOST, user="NT AUTHORITY\\SYSTEM")
    d.proc(d.at(3, 30), "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MpCmdRun.exe",
           '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MpCmdRun.exe" -IdleTask -TaskName WdCacheMaintenance',
           parent=SVCHOST, user="NT AUTHORITY\\SYSTEM")
    if rng.random() < 0.15:  # occasional legitimate service update
        d.system(d.at(rng.uniform(1, 5)), 7045, ServiceName="gupdate", ImagePath='"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe" /svc',
                 ServiceType="user mode service", StartType="auto start", AccountName="LocalSystem")
    if rng.random() < 0.1:
        d.system(d.at(rng.uniform(1, 5)), 7045, ServiceName="MicrosoftEdgeElevationService",
                 ImagePath='"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\130.0.2849.56\\elevation_service.exe"',
                 ServiceType="user mode service", StartType="demand start", AccountName="LocalSystem")


def _sccm(d: _Day) -> None:
    """Configuration Manager runs encoded PowerShell. The rule filters CcmExec."""
    for hour in (7, 13):
        d.proc(d.at(hour, 40), PS,
               "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Bypass -enc "
               "JABFAHIAcgBvAHIAQQBjAHQAaQBvAG4AUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwA=",
               parent="C:\\Windows\\CCM\\CcmExec.exe", user="NT AUTHORITY\\SYSTEM", ofn="PowerShell.EXE")


def _user_day(d: _Day) -> None:
    rng, host = d.rng, d.host
    start = d.at(8.7, 35)
    # interactive logon
    d.security(start, 4624, TargetUserName=host.user, TargetDomainName="CORP", LogonType="2",
               IpAddress="127.0.0.1", LogonProcessName="User32", AuthenticationPackageName="Negotiate")
    if rng.random() < 0.3:  # mistyped password first
        for i in range(rng.randint(1, 3)):
            d.security(start - timedelta(seconds=20 * (i + 1)), 4625, TargetUserName=host.user, LogonType="2",
                       IpAddress="127.0.0.1", Status="0xc000006d", SubStatus="0xc000006a")
    d.proc(start + timedelta(seconds=3), "C:\\Windows\\System32\\userinit.exe", "C:\\Windows\\system32\\userinit.exe",
           parent="C:\\Windows\\System32\\winlogon.exe")
    d.proc(start + timedelta(seconds=4), EXPLORER, "C:\\Windows\\Explorer.EXE", parent="C:\\Windows\\System32\\userinit.exe")
    onedrive = f"{host.home}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"
    d.proc(start + timedelta(seconds=9), onedrive, f'"{onedrive}" /background')
    if rng.random() < 0.5:
        d.reg(start + timedelta(seconds=11), onedrive, _hkcu_run(host) + "OneDrive", f'"{onedrive}" /background')
    teams_update = f"{host.home}\\AppData\\Local\\Microsoft\\Teams\\Update.exe"
    d.proc(start + timedelta(seconds=12), teams_update, f'{teams_update} --processStart "Teams.exe" --process-start-args "--system-initiated"')
    if rng.random() < 0.35:
        d.reg(start + timedelta(seconds=14), teams_update, _hkcu_run(host) + "com.squirrel.Teams.Teams",
              f'{teams_update} --processStart "Teams.exe" --process-start-args "--system-initiated"')
    for app, exe, run_name, details, prob in (
        ("spotify", f"{host.home}\\AppData\\Roaming\\Spotify\\Spotify.exe", "Spotify",
         f'"{host.home}\\AppData\\Roaming\\Spotify\\Spotify.exe" --autostart --minimized', 0.4),
        ("zoom", f"{host.home}\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe", "ZoomUpdater",
         f'"{host.home}\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe" --autostart', 0.2),
        ("slack", f"{host.home}\\AppData\\Local\\slack\\slack.exe", "com.squirrel.slack.slack",
         f'"{host.home}\\AppData\\Local\\slack\\slack.exe" --process-start-args --startup', 0.3),
        ("discord", f"{host.home}\\AppData\\Local\\Discord\\Update.exe", "Discord",
         f'"{host.home}\\AppData\\Local\\Discord\\Update.exe" --processStart Discord.exe', 0.3),
    ):
        if app in host.roles:
            d.proc(start + timedelta(seconds=15), exe, f'"{exe}"')
            if rng.random() < prob:
                d.reg(start + timedelta(seconds=17), exe, _hkcu_run(host) + run_name, details)
    if "developer" in host.roles and rng.random() < 0.08:
        # GitHub Desktop is not in the rule's filter list: a real, unfiltered benign hit.
        gh = f"{host.home}\\AppData\\Local\\GitHubDesktop\\Update.exe"
        d.reg(start + timedelta(seconds=19), gh, _hkcu_run(host) + "GitHubDesktop", f'{gh} --processStart "GitHubDesktop.exe"')

    # browsing and office work
    for _ in range(rng.randint(6, 14)):
        when = d.work_time()
        browser = rng.choice([CHROME, EDGE])
        d.proc(when, browser, f'"{browser}"')
        for _ in range(rng.randint(3, 9)):
            d.proc(when + timedelta(seconds=rng.randint(1, 30)), browser,
                   f'"{browser}" --type=renderer --lang=en-US --renderer-client-id={rng.randint(5, 400)} --launch-time-ticks={rng.randint(10**9, 10**10)}',
                   parent=browser)
        d.pipe(when, browser, f"\\mojo.{rng.randint(1000, 9999)}.{rng.randint(1000, 99999)}.{rng.randint(10**10, 10**11)}")
        for _ in range(rng.randint(4, 12)):
            d.dns(when + timedelta(seconds=rng.randint(0, 600)), browser, rng.choice(COMMON_DOMAINS))
    for _ in range(rng.randint(2, 6)):
        when = d.work_time()
        app = rng.choice(["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE"])
        doc = rng.choice(["Q3 report.docx", "budget.xlsx", "minutes.docx", "roadmap.pptx", "invoice-template.xlsx"])
        d.proc(when, OFFICE + app, f'"{OFFICE}{app}" /n "{host.home}\\Documents\\{doc}"')
        if rng.random() < 0.15:
            d.proc(when + timedelta(minutes=3), "C:\\Windows\\splwow64.exe", "C:\\Windows\\splwow64.exe 12288", parent=OFFICE + app)
    d.proc(d.at(9.1, 20), OFFICE + "OUTLOOK.EXE", f'"{OFFICE}OUTLOOK.EXE"')
    if rng.random() < 0.3:
        d.proc(d.work_time(), EDGE, f'"{EDGE}" --single-argument https://intranet.corp.local/news', parent=OFFICE + "OUTLOOK.EXE")
    # mapped drives on the file server
    for _ in range(rng.randint(2, 6)):
        when = d.work_time()
        d.net(when, "System", "10.10.10.21", 445, "SRV-FILE01")
    d.security(d.at(17.6, 30), 4634, TargetUserName=host.user, LogonType="2")


def _developer(d: _Day) -> None:
    rng, host = d.rng, d.host
    code = f"{host.home}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"
    d.proc(d.at(9.3), code, f'"{code}"')
    for _ in range(rng.randint(5, 15)):
        when = d.work_time()
        choice = rng.random()
        if choice < 0.4:
            d.proc(when, "C:\\Program Files\\Git\\cmd\\git.exe", rng.choice([
                "git status", "git pull --rebase", "git log --oneline -20", "git commit -m wip", "git push origin HEAD",
            ]), parent=code)
            d.dns(when, "C:\\Program Files\\Git\\mingw64\\bin\\git-remote-https.exe", "github.com")
        elif choice < 0.6:
            d.proc(when, PS, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Import-Module 'c:\\Users\\dev\\.vscode\\shellIntegration.ps1'\"",
                   parent=code, ofn="PowerShell.EXE")
            d.pipe(when, PS, f"\\PSHost.{rng.randint(10**17, 10**18)}.{rng.randint(1000, 9999)}.DefaultAppDomain.powershell")
        elif choice < 0.8:
            d.proc(when, "C:\\Program Files\\nodejs\\node.exe", rng.choice([
                "node.exe node_modules\\.bin\\vite", "node.exe node_modules\\jest\\bin\\jest.js --watch", "node.exe server.js",
            ]), parent=CMD)
            d.dns(when, "C:\\Program Files\\nodejs\\node.exe", "registry.npmjs.org")
        else:
            d.proc(when, f"{host.home}\\AppData\\Local\\Programs\\Python\\Python312\\python.exe",
                   rng.choice(["python.exe -m pytest -q", "python.exe manage.py runserver", "python.exe -m pip install -r requirements.txt"]),
                   parent=CMD)
            d.dns(when, f"{host.home}\\AppData\\Local\\Programs\\Python\\Python312\\python.exe", "pypi.org")
        if rng.random() < 0.05:
            d.proc(when, "C:\\Windows\\System32\\certutil.exe", f"certutil -hashfile {host.home}\\Downloads\\node-v22.11.0-x64.msi SHA256",
                   parent=CMD, ofn="CertUtil.exe")
    if rng.random() < 0.12:
        # a teammate shares a local demo over ngrok
        d.dns(d.work_time(), CHROME, f"{rng.randint(1000, 9999):x}-81-2-69-{rng.randint(10, 250)}.ngrok-free.app")


def _finance(d: _Day) -> None:
    if d.rng.random() < 0.15:
        when = d.work_time()
        d.proc(when, CMD, 'cmd.exe /c "C:\\Finance\\Macros\\export_ledger.bat"', parent=OFFICE + "EXCEL.EXE")


def _itadmin(d: _Day) -> None:
    rng = d.rng
    d.proc(d.at(9.2), PS, "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\IT\\inventory.ps1", ofn="PowerShell.EXE")
    for _ in range(rng.randint(3, 8)):
        when = d.work_time()
        image, cmd = rng.choice([
            ("C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all"),
            ("C:\\Windows\\System32\\gpupdate.exe", "gpupdate /force"),
            ("C:\\Windows\\System32\\net.exe", f"net user {rng.choice(['alice', 'bob', 'carol', 'heidi'])} /domain"),
            ("C:\\Windows\\System32\\nltest.exe", "nltest /dsgetdc:corp.local"),
            ("C:\\Windows\\System32\\schtasks.exe", "schtasks /query /fo LIST /v"),
            ("C:\\Windows\\System32\\wevtutil.exe", "wevtutil qe System /c:20 /rd:true /f:text"),
            ("C:\\Windows\\System32\\whoami.exe", "whoami"),
            ("C:\\Windows\\System32\\mmc.exe", '"C:\\Windows\\system32\\mmc.exe" "C:\\Windows\\system32\\compmgmt.msc" /s'),
        ])
        d.proc(when, image, cmd, parent=CMD)
    if rng.random() < 0.35:
        d.proc(d.work_time(), "C:\\Windows\\System32\\whoami.exe", "whoami /groups", parent=CMD)
    if rng.random() < 0.15:
        d.access(d.work_time(), "C:\\Windows\\System32\\Taskmgr.exe", LSASS, "0x1410")


def _itadmin_remote(day_rng: random.Random, days: dict[str, _Day]) -> None:
    """Cross-host admin actions: PsExec to a workstation, local-admin grants."""
    targets = [n for n in days if n.startswith("WS-") and n != "WS-009"]
    if day_rng.random() < 0.2:
        target = days[day_rng.choice(targets)]
        when = target.work_time()
        target.pipe(when, "C:\\Windows\\PSEXESVC.exe", "\\PSEXESVC")
        target.pipe(when, "C:\\Windows\\PSEXESVC.exe", f"\\PSEXESVC-WS-009-{day_rng.randint(1000, 9999)}-stdin")
        target.system(when, 7045, ServiceName="PSEXESVC", ImagePath="%SystemRoot%\\PSEXESVC.exe",
                      ServiceType="user mode service", StartType="demand start", AccountName="LocalSystem")
        target.proc(when, CMD, "cmd /c gpupdate /force", parent="C:\\Windows\\PSEXESVC.exe", user="CORP\\it.admin")
    if day_rng.random() < 0.12:
        target = days[day_rng.choice(targets)]
        target.security(target.work_time(), 4732, TargetSid="S-1-5-32-544", TargetUserName="Administrators",
                        MemberSid=f"S-1-5-21-1111111111-2222222222-3333333333-{day_rng.randint(1200, 1300)}",
                        SubjectUserName="it.admin")


def _fileserver(d: _Day) -> None:
    rng = d.rng
    d.proc(d.at(1.0, 5), "C:\\Tools\\rclone\\rclone.exe",
           "rclone.exe sync D:\\Shares s3backup:corp-backups --config C:\\ProgramData\\rclone\\rclone.conf --log-file C:\\Logs\\rclone.log",
           parent=SVCHOST, user="NT AUTHORITY\\SYSTEM", desc="Rsync for cloud storage")
    d.proc(d.at(0.5, 5), "C:\\Windows\\System32\\vssadmin.exe", "vssadmin list shadows", parent=CMD, user="CORP\\svc.backup")
    d.proc(d.at(0.6, 5), "C:\\Windows\\System32\\vssadmin.exe", "vssadmin create shadow /for=D:", parent=CMD, user="CORP\\svc.backup")
    for _ in range(rng.randint(30, 60)):
        ws = rng.choice(HOSTS[:9])
        d.security(d.work_time(), 4624, TargetUserName=ws.user, TargetDomainName="CORP", LogonType="3",
                   IpAddress=ws.ip, LogonProcessName="Kerberos", AuthenticationPackageName="Kerberos")


def _domain_controller(d: _Day, stale_service_account: bool) -> None:
    rng = d.rng
    for _ in range(rng.randint(150, 250)):
        ws = rng.choice(HOSTS[:9])
        d.security(d.work_time(), 4624, TargetUserName=ws.user, TargetDomainName="CORP", LogonType="3",
                   IpAddress=ws.ip, LogonProcessName="Kerberos", AuthenticationPackageName="Kerberos")
    for _ in range(rng.randint(0, 6)):  # users typing a wrong password over RDP / SMB
        ws = rng.choice(HOSTS[:9])
        when = d.work_time()
        for i in range(rng.randint(1, 3)):
            d.security(when + timedelta(seconds=10 * i), 4625, TargetUserName=ws.user, LogonType="3",
                       IpAddress=ws.ip, Status="0xc000006d", SubStatus="0xc000006a")
        d.security(when + timedelta(seconds=45), 4624, TargetUserName=ws.user, TargetDomainName="CORP", LogonType="3",
                   IpAddress=ws.ip, LogonProcessName="NtLmSsp", AuthenticationPackageName="NTLM")
    if stale_service_account:
        # svc.sql still has its old password on SRV-APP01: one failure every 15 minutes.
        base = datetime(d.day.year, d.day.month, d.day.day, tzinfo=timezone.utc)
        for quarter in range(96):
            d.security(base + timedelta(minutes=15 * quarter, seconds=rng.randint(0, 20)), 4625,
                       TargetUserName="svc.sql", LogonType="3", IpAddress="10.10.30.5",
                       Status="0xc000006d", SubStatus="0xc000006a")


def _app_server(d: _Day) -> None:
    for hour in range(0, 24, 4):
        d.proc(d.at(hour + 0.1, 5), "C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe",
               '"C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe" -sMSSQLSERVER',
               parent=SERVICES, user="NT SERVICE\\MSSQLSERVER")


# ---------------------------------------------------------------------------

def _simulate(hosts: list[Host], days: int, seed: int, start: date) -> Iterator[dict[str, Any]]:
    rng = random.Random(seed)
    for offset in range(days):
        day = start + timedelta(days=offset)
        workday = day.weekday() < 5
        day_rng = random.Random(rng.randint(0, 2**31))
        stale = offset in (2, 3)  # the service-account password was rotated mid-week
        per_host = {h.name: _Day(random.Random(day_rng.randint(0, 2**31)), h, day) for h in hosts}
        for host in hosts:
            d = per_host[host.name]
            _system_background(d, workday)
            if host.user and "office" in host.roles:
                _sccm(d)
            if workday and host.user:
                _user_day(d)
                if "developer" in host.roles:
                    _developer(d)
                if "finance" in host.roles:
                    _finance(d)
                if "itadmin" in host.roles:
                    _itadmin(d)
            if "fileserver" in host.roles:
                _fileserver(d)
            if "dc" in host.roles:
                _domain_controller(d, stale_service_account=stale)
            if "app" in host.roles:
                _app_server(d)
        if workday and any(h.name == "WS-009" for h in hosts):
            _itadmin_remote(day_rng, per_host)
        day_events = [ev for d in per_host.values() for ev in d.events]
        day_events.sort(key=lambda e: (e["@timestamp"], e["Computer"], e["EventID"]))
        yield from day_events


def generate(out_dir: Path, hosts: int = len(HOSTS), days: int = 14, seed: int = 1337,
             start: date = date(2026, 9, 7)) -> CorpusInfo:
    """Write ``synthetic-baseline.jsonl.gz`` and ``corpus.json`` into ``out_dir``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    selected = HOSTS[:hosts]
    path = out_dir / "synthetic-baseline.jsonl.gz"
    count = 0
    first = last = ""
    with open(path, "wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as gz:
            for ev in _simulate(selected, days, seed, start):
                gz.write((json.dumps(ev, sort_keys=True) + "\n").encode("utf-8"))
                count += 1
                first = first or ev["@timestamp"]
                last = ev["@timestamp"]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    info = CorpusInfo(path=path, hosts=len(selected), days=days, start=first, end=last, seed=seed,
                      events=count, sha256=digest)
    (out_dir / "corpus.json").write_text(json.dumps(info.to_json(), indent=2) + "\n", encoding="utf-8")
    return info
