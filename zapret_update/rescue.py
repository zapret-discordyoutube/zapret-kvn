"""Страховка замены файлов: откат доводится, даже если программа без exe.

Неудачная замена, откат которой упёрся в занятый файл, оставляет файлы
прежней версии в ``swap/old`` и журнал на диске. Довести откат может
запущенная программа — но без своего exe она не запускается, и вернуть
себя некому. Поэтому перед заменой ставится разовая задача Windows
(``RunOnce``): при следующем входе в систему маленький сценарий PowerShell
проходит тот же журнал назад, как ``swap.recover``, и запускает программу.
Не вышло — ставит себя снова. Удачная замена или доведённый откат задачу
снимают.

Безопасность: сценарий выполняется с правами администратора, поэтому он и
его настройки лежат в каталоге, закрытом от записи обычными пользователями
(``harden_commands``), а из журнала (он в папке программы) переносятся
только файлы внутри папки программы и не через точки повторной обработки
(соединения, ссылки).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
from pathlib import Path

try:
    import winreg
except ImportError:  # не Windows: страховки нет
    winreg = None

_log = logging.getLogger("zapret_update.rescue")

RUNONCE_KEY = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
SCRIPT_NAME = "rescue.ps1"
_VALUE_PREFIX = "ZapretUpdateRescue-"

# Хорошо известные SID: они одинаковы в любой локализации Windows.
_SID_SYSTEM = "*S-1-5-18"
_SID_ADMINISTRATORS = "*S-1-5-32-544"
_SID_USERS = "*S-1-5-32-545"

SCRIPT = r"""param([Parameter(Mandatory = $true)][string]$Name)
# Страховка замены файлов Zapret: довести откат по журналу и запустить программу.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$settingsPath = Join-Path $here ($Name + '.json')
$logPath = Join-Path $here ($Name + '.log')
$runOnce = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'

function Write-Line([string]$text) {
    try { Add-Content -LiteralPath $logPath -Value ('{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $text) -Encoding UTF8 } catch { }
}
function Disarm {
    Remove-ItemProperty -Path $runOnce -Name $Name -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $settingsPath -ErrorAction SilentlyContinue
}

try {
    $settings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
    Disarm
    exit 0
}
$app = [IO.Path]::GetFullPath([string]$settings.app_dir).TrimEnd('\') + '\'
$journalPath = Join-Path ([IO.Path]::GetFullPath([string]$settings.swap_dir)) 'journal.json'

function Test-Inside([string]$path) {
    $full = [IO.Path]::GetFullPath($path)
    if (-not $full.StartsWith($app, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    # Ни одна часть пути внутри папки программы не должна быть соединением или ссылкой.
    $probe = $full
    while ($probe.Length -ge $app.Length) {
        if (Test-Path -LiteralPath $probe) {
            $item = Get-Item -LiteralPath $probe -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        }
        $probe = Split-Path -Parent $probe
        if (-not $probe) { break }
    }
    return $true
}

if (-not (Test-Path -LiteralPath $journalPath)) {
    Write-Line 'журнала нет: откат уже доведён'
    Disarm
    exit 0
}
$journal = Get-Content -LiteralPath $journalPath -Raw -Encoding UTF8 | ConvertFrom-Json
$moves = @()
if ($null -ne $journal.moves) { $moves = $journal.moves }
if ($moves.Count -gt 0 -and -not ($moves[0] -is [array])) { $moves = ,$moves }
$created = @()
if ($null -ne $journal.created_dirs) { $created = @($journal.created_dirs) }

# Программа (её прежние или новые процессы) не должна держать файлы.
Get-CimInstance Win32_Process | Where-Object {
    $_.ExecutablePath -and $_.ExecutablePath.StartsWith($app, [StringComparison]::OrdinalIgnoreCase)
} | ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force } catch { } }
Start-Sleep -Milliseconds 500

$remaining = New-Object System.Collections.ArrayList
$stuck = @{}
for ($i = $moves.Count - 1; $i -ge 0; $i--) {
    $move = $moves[$i]
    $current = [string]$move[0]
    $origin = [string]$move[1]
    if (-not (Test-Inside $current) -or -not (Test-Inside $origin)) {
        Write-Line "пропущено вне папки программы: $origin"
        continue
    }
    if (-not (Test-Path -LiteralPath $current -PathType Leaf)) { continue }
    if ($move.Count -ge 4) {
        $item = Get-Item -LiteralPath $current -Force
        $ns = ($item.LastWriteTimeUtc.Ticks - 621355968000000000) * 100
        if ($item.Length -ne [int64]$move[2] -or $ns -ne [int64]$move[3]) { continue }
    }
    if (Test-Path -LiteralPath $origin -PathType Leaf) {
        if ($stuck.ContainsKey($origin.ToLowerInvariant())) { [void]$remaining.Insert(0, $move) }
        continue
    }
    try {
        if (Test-Path -LiteralPath $origin -PathType Container) {
            Get-ChildItem -LiteralPath $origin -Recurse -Directory -Force |
                Sort-Object { $_.FullName.Length } -Descending | ForEach-Object { Remove-Item -LiteralPath $_.FullName }
            Remove-Item -LiteralPath $origin
        }
        $parent = Split-Path -Parent $origin
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        [IO.File]::Move($current, $origin)
    } catch {
        [void]$remaining.Insert(0, $move)
        $stuck[$current.ToLowerInvariant()] = $true
        Write-Line "не вернулся: $origin — $($_.Exception.Message)"
    }
}

if ($remaining.Count -gt 0) {
    $items = foreach ($move in $remaining) { '[' + (($move | ForEach-Object { ConvertTo-Json $_ -Compress }) -join ',') + ']' }
    $dirs = foreach ($dir in $created) { ConvertTo-Json ([string]$dir) -Compress }
    $text = '{"app_dir":' + (ConvertTo-Json ([string]$journal.app_dir) -Compress) + ',"moves":[' + ($items -join ',') +
        '],"created_dirs":[' + ($dirs -join ',') + ']}'
    [IO.File]::WriteAllText($journalPath, $text, (New-Object Text.UTF8Encoding $false))
    Set-ItemProperty -Path $runOnce -Name $Name -Value ([string]$settings.command)
    Write-Line "откат не доведён, осталось $($remaining.Count): повтор при следующем входе"
    exit 1
}

for ($i = $created.Count - 1; $i -ge 0; $i--) {
    try { Remove-Item -LiteralPath ([string]$created[$i]) } catch { }
}
Remove-Item -LiteralPath $journalPath -ErrorAction SilentlyContinue
Disarm
Write-Line 'откат доведён: прежняя версия на месте'
$start = @($settings.start)
if ($start.Count -gt 0 -and (Test-Path -LiteralPath ([string]$start[0]) -PathType Leaf)) {
    $arguments = @($start | Select-Object -Skip 1)
    if ($arguments.Count -gt 0) {
        Start-Process -FilePath ([string]$start[0]) -ArgumentList $arguments -WorkingDirectory (Split-Path -Parent ([string]$start[0]))
    } else {
        Start-Process -FilePath ([string]$start[0]) -WorkingDirectory (Split-Path -Parent ([string]$start[0]))
    }
}
exit 0
"""


def value_name(app_dir: str | Path) -> str:
    """Имя записи RunOnce своё у каждой папки программы (Dev и Stable не мешают друг другу)."""
    key = os.path.normcase(os.path.abspath(str(app_dir)))
    return _VALUE_PREFIX + hashlib.blake2b(key.encode("utf-8"), digest_size=6).hexdigest()


def harden_commands(directory: str | Path) -> tuple[tuple[str, ...], ...]:
    """Команды icacls, закрывающие каталог от записи обычными пользователями.

    Порядок важен: сначала каталог получает явный список прав (с этого
    момента подложить файл нельзя), потом владельцем содержимого становятся
    администраторы, потом права содержимого сбрасываются к наследуемым.
    ``/T`` на первом шаге нельзя: флаги ``(OI)(CI)`` к файлу не применяются.
    """
    target = str(directory)
    return (
        (
            "icacls", target, "/inheritance:r", "/grant:r",
            f"{_SID_SYSTEM}:(OI)(CI)F", f"{_SID_ADMINISTRATORS}:(OI)(CI)F", f"{_SID_USERS}:(OI)(CI)RX",
            "/C", "/Q",
        ),
        ("icacls", target, "/setowner", _SID_ADMINISTRATORS, "/T", "/C", "/Q"),
        ("icacls", str(Path(target) / "*"), "/reset", "/T", "/C", "/Q"),
    )


def _harden(directory: Path) -> bool:
    for command in harden_commands(directory):
        try:
            completed = subprocess.run(
                list(command), capture_output=True, timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError):
            return False
        if completed.returncode != 0:
            return False
    return True


def command_line(rescue_dir: str | Path, name: str) -> str:
    """Короткая строка для RunOnce: Windows режет её на 260 знаках."""
    script = Path(rescue_dir) / SCRIPT_NAME
    return subprocess.list2cmdline([
        "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden", "-File", str(script), name,
    ])


def write_files(rescue_dir: str | Path, name: str, *, app_dir, swap_dir, start: list[str]) -> str:
    """Положить сценарий и его настройки; вернуть строку запуска."""
    directory = Path(rescue_dir)
    directory.mkdir(parents=True, exist_ok=True)
    command = command_line(directory, name)
    (directory / SCRIPT_NAME).write_text(SCRIPT, encoding="utf-8-sig")
    settings = {
        "app_dir": str(app_dir), "swap_dir": str(swap_dir), "start": [str(part) for part in start], "command": command,
    }
    (directory / f"{name}.json").write_text(json.dumps(settings, ensure_ascii=False), encoding="utf-8")
    return command


def arm(rescue_dir: str | Path, *, app_dir, swap_dir, start: list[str]) -> bool:
    """Поставить страховку перед заменой файлов. False — не Windows или не вышло."""
    if winreg is None or not rescue_dir:
        return False
    name = value_name(app_dir)
    try:
        directory = Path(rescue_dir)
        directory.mkdir(parents=True, exist_ok=True)
        if not _harden(directory):
            _log.warning("Каталог страховки не закрыт от записи — страховка не ставится: %s", directory)
            return False
        command = write_files(directory, name, app_dir=app_dir, swap_dir=swap_dir, start=start)
        if len(command) > 259:
            _log.warning("Строка страховки длиннее 259 знаков — не ставится: %s", command)
            return False
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, RUNONCE_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)
    except OSError as error:
        _log.warning("Страховка замены не поставлена: %s", error)
        return False
    _log.info("Страховка замены поставлена: %s", name)
    return True


def disarm(rescue_dir: str | Path, app_dir) -> None:
    """Снять страховку: замена удалась или откат доведён."""
    if winreg is None:
        return
    name = value_name(app_dir)
    try:
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, RUNONCE_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass
    except OSError as error:
        _log.warning("Страховка замены не снята: %s", error)
    if rescue_dir:
        try:
            (Path(rescue_dir) / f"{name}.json").unlink(missing_ok=True)
        except OSError:
            pass


__all__ = ["SCRIPT", "arm", "command_line", "disarm", "harden_commands", "value_name", "write_files"]
