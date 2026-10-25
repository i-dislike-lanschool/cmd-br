#!/usr/bin/env python3
"""Cmd Bridge — безопасное выполнение команд из чата с подтверждением.

Сценарий использования:

1. Ассистент в чате предлагает команду (в блоке кода).
2. Пользователь копирует её (кнопка "копировать" или Ctrl+C).
3. Cmd Bridge сам подхватывает текст из буфера обмена, показывает его,
   снимает markdown-обёртки (```...```), предупреждает об опасных
   операциях и спрашивает подтверждение.
4. После подтверждения команда выполняется в этом же окне, вывод виден
   сразу; его можно скопировать обратно в буфер и вернуть ассистенту.

Только стандартная библиотека Python, без внешних зависимостей.
На не-Windows системах работает в режиме ручного ввода (вставка в консоль).
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

APP_TITLE = "Cmd Bridge — Free Model Radar"
POLL_SECONDS = 0.4
MAX_CLIPBOARD_COMMAND_CHARS = 20_000
MAX_OUTPUT_COPY_CHARS = 256_000
HISTORY_NAME = "cmd_bridge_history.log"

# ---------------------------------------------------------------------------
# Разбор и классификация команд (чистые функции, тестируются без Windows)
# ---------------------------------------------------------------------------

FENCE_OPEN_RE = re.compile(r"^```([A-Za-z0-9_+\-]*)\s*$")
POWERSHELL_HINTS = (
    "$env:",
    "invoke-webrequest",
    "invoke-restmethod",
    "invoke-expression",
    "set-executionpolicy",
    "get-childitem",
    "get-content",
    "set-content",
    "add-content",
    "remove-item",
    "new-item",
    "start-process",
    "write-host",
    "write-output",
    "foreach-object",
    "where-object",
    "select-object",
    "expand-archive",
    "join-path",
    "test-path",
    "[environment]::",
    "[system.",
    "-executionpolicy",
    "powershell -command",
    "pwsh -command",
)
FENCE_POWERSHELL = {"powershell", "ps1", "pwsh"}
FENCE_CMD = {"cmd", "bat", "batch", "dos", "console"}
FENCE_UNIX = {"bash", "sh", "shell", "zsh", "fish"}

DANGER_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bformat\s+[a-z]:", "форматирование диска"),
    (r"\bdiskpart\b", "работа с разделами диска (diskpart)"),
    (r"\b(del|erase)\b[^\n]*\s/s\b", "рекурсивное удаление файлов (del /s)"),
    (r"\b(rmdir|rd)\b[^\n]*\s/s\b", "рекурсивное удаление каталогов (rd /s)"),
    (r"remove-item[^\n]*-recurse", "рекурсивное удаление (Remove-Item -Recurse)"),
    (r"\brm\s+-[a-z]*r[a-z]*f\b|\brm\s+-[a-z]*f[a-z]*r\b", "принудительное рекурсивное удаление (rm -rf)"),
    (r"\bshutdown\b\s*/[sr]", "выключение или перезагрузка компьютера"),
    (r"\bbcdedit\b", "редактирование загрузчика (bcdedit)"),
    (r"\breg\s+(delete|add)\b", "изменение реестра (reg)"),
    (r"set-itemproperty[^\n]*hklm", "изменение реестра (HKLM)"),
    (r"\btakeown\b", "смена владельца файлов (takeown)"),
    (r"\bicacls\b[^\n]*(/reset|/grant|/remove)", "изменение прав доступа (icacls)"),
    (r"\bnet\s+(user|localgroup)\b", "изменение учётных записей (net user)"),
    (r"\binvoke-expression\b|\biex\s+[\($]", "выполнение произвольного кода (Invoke-Expression)"),
    (r"\bsfc\b|\bdism\b", "обслуживание системных компонентов (sfc/dism)"),
)


@dataclass
class CommandPlan:
    """Команда, подготовленная к выполнению."""

    text: str
    dialect: str  # "cmd" | "ps1" | "sh"
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    signed: bool = False
    envelope_issue: str | None = None
    is_output: bool = False


# ---------------------------------------------------------------------------
# Подпись FMR-BRIDGE: конверты с контрольной суммой
# ---------------------------------------------------------------------------

BRIDGE_OPEN_RE = re.compile(r"^-----FMR-BRIDGE v1 sha1:([0-9a-f]{40})-----$")
BRIDGE_CLOSE_RE = re.compile(r"^-----END FMR-BRIDGE-----$")
BRIDGE_OUT_OPEN_RE = re.compile(r"^-----FMR-BRIDGE-OUT v1 exit:(-?\d+) sha1:([0-9a-f]{40})-----$")
BRIDGE_OUT_CLOSE_RE = re.compile(r"^-----END FMR-BRIDGE-OUT-----$")
BRIDGE_INFO_OPEN_RE = re.compile(r"^-----FMR-BRIDGE-INFO v1-----$")
BRIDGE_INFO_CLOSE_RE = re.compile(r"^-----END FMR-BRIDGE-INFO-----$")


def normalize_for_hash(text: str) -> str:
    """Канонический вид текста для подсчёта суммы: не зависит от концов строк
    и хвостовых пробелов, которые могут потеряться при копировании."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    lines = [ln.rstrip() for ln in lines]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def hash_text(text: str) -> str:
    return hashlib.sha1(normalize_for_hash(text).encode("utf-8")).hexdigest()


def extract_envelope(text: str) -> tuple[str, str, str] | None:
    """Ищет конверт подписи в тексте.

    Возвращает (тип, заявленная сумма, тело) или None, если конверта нет.
    тип: "cmd" — входящая команда, "out" — вывод моста,
    "protocol" — протокол сессии. Незакрытый конверт считается отсутствующим.
    """
    lines = text.split("\n")
    open_idx = None
    kind = None
    sha = ""
    for i, line in enumerate(lines):
        stripped = line.strip()
        m = BRIDGE_OPEN_RE.match(stripped)
        if m:
            open_idx, kind, sha = i, "cmd", m.group(1)
            break
        m = BRIDGE_OUT_OPEN_RE.match(stripped)
        if m:
            open_idx, kind, sha = i, "out", m.group(2)
            break
        m = BRIDGE_INFO_OPEN_RE.match(stripped)
        if m:
            open_idx, kind, sha = i, "info", ""
            break
    if open_idx is None:
        return None
    close_re = {"cmd": BRIDGE_CLOSE_RE, "out": BRIDGE_OUT_CLOSE_RE,
                "info": BRIDGE_INFO_CLOSE_RE}[kind]
    for j in range(open_idx + 1, len(lines)):
        if close_re.match(lines[j].strip()):
            body = "\n".join(lines[open_idx + 1 : j])
            return kind, sha, body
    return None


def wrap_output(output: str, exit_code: int) -> str:
    """Заворачивает вывод в подписанный конверт для обратной передачи."""
    body = output.rstrip("\r\n")
    sha = hash_text(body)
    return (
        f"-----FMR-BRIDGE-OUT v1 exit:{exit_code} sha1:{sha}-----\n"
        f"{body}\n"
        f"-----END FMR-BRIDGE-OUT-----\n\n\n"
    )


# ---------------------------------------------------------------------------
# Инструкция для другой модели/агента: как общаться через этот мост
# ---------------------------------------------------------------------------

AI_INSTRUCTIONS_TEXT = """\
Инструкция для ИИ/агента: командный мост FMR-BRIDGE (Free Model Radar)

Что это. У пользователя на Windows запущен «мост» — консольная утилита
cmd_bridge.py из репозитория i-dislike-lanschool/cmd-br
(папка tools/cmd-bridge). Пользователь копирует твои команды из чата,
мост подхватывает их из буфера обмена и выполняет на его машине ТОЛЬКО
после его ручного подтверждения. Ты не имеешь прямого доступа к машине —
каждый запуск подтверждает человек.

Как слать команды. Каждую команду оборачивай в подписанный конверт:

-----FMR-BRIDGE v1 sha1:<сумма>-----
<тело команды, одна или несколько строк>
-----END FMR-BRIDGE-----

<сумма> — SHA-1 (hex) от нормализованного тела: концы строк приводятся
к \\n, хвостовые пробелы строк удаляются, пустые строки в начале и в
конце отбрасываются, кодировка UTF-8. Мост проверяет сумму; конверт с
неверной суммой или без конверта выполнен не будет. Команды для
командной строки и скриптов допустимы любые (мост сам определит диалект
и выполнит через cmd.exe или PowerShell), но не используй строки,
начинающиеся с пяти дефисов, внутри тела.

Что приходит обратно. После выполнения мост автоматически копирует в
буфер обмена вывод в конверте:

-----FMR-BRIDGE-OUT v1 exit:<код выхода> sha1:<сумма вывода>-----
<вывод команды>
-----END FMR-BRIDGE-OUT-----

Поля: exit — код выхода (0 обычно успех), сумма считается по тем же
правилам нормализации; по ней можно убедиться, что вывод дошёл без
обрезки. Если пользователь прислал текст без такого конверта — это не
вывод моста.

Правила безопасности. Ничего не выполняется без подтверждения
пользователя. Опасные операции (форматирование, рекурсивное удаление,
правка реестра, выключение и т.п.) мост помечает и требует от
пользователя двойного подтверждения. Формулируй команды максимально
точно и не проси обходные пути. Если команде нужны секреты (токены и
т.п.), не вставляй их в текст команды — пусть пользователь задаст их
через переменные окружения.

Стиль. Давай за один раз одну команду (или один короткий скрипт), жди
вывод, затем предлагай следующий шаг. Вместе с конвертом можно
показывать пояснения обычным текстом — мост берёт из буфера только
сам конверт."""


def ai_instructions_envelope() -> str:
    return (
        "-----FMR-BRIDGE-INFO v1-----\n"
        f"{AI_INSTRUCTIONS_TEXT.rstrip()}\n"
        "-----END FMR-BRIDGE-INFO-----"
    )


def copy_ai_instructions(clipboard) -> bool:
    text = ai_instructions_envelope()
    if clipboard is None:
        print("Буфер обмена недоступен — печатаю инструкцию в окно:")
        print(text)
        return False
    if clipboard.write(text):
        print("Инструкция для ИИ скопирована в буфер обмена (конверт")
        print("FMR-BRIDGE-INFO) — вставьте её в чат другой модели/агенту.")
        return True
    print("Не удалось скопировать инструкцию в буфер обмена.")
    return False


def strip_code_fences(text: str) -> tuple[str, str]:
    """Убирают markdown-обёртку вида ```lang ... ```.

    Возвращает (язык_блока, тело). Если текст не обёрнут в блок целиком —
    возвращает ("", исходный текст).
    """
    lines = text.splitlines()
    # Ищем первую непустую строку.
    first = next((i for i, ln in enumerate(lines) if ln.strip()), None)
    if first is None:
        return "", text.strip()
    m = FENCE_OPEN_RE.match(lines[first].strip())
    if not m:
        return "", text.strip()
    # Последняя непустая строка должна быть закрывающим ```.
    last = next((i for i in range(len(lines) - 1, first, -1) if lines[i].strip()), None)
    if last is None or lines[last].strip() != "```":
        return "", text.strip()
    body = "\n".join(lines[first + 1 : last])
    return m.group(1).strip().lower(), body.strip()


def looks_like_powershell(text: str) -> bool:
    low = text.lower()
    return any(hint in low for hint in POWERSHELL_HINTS)


def classify_command(text: str) -> str:
    """Определяет диалект: "ps1", "cmd" или "sh"."""
    lang, body = strip_code_fences(text)
    if lang in FENCE_POWERSHELL:
        return "ps1"
    if lang in FENCE_CMD:
        return "cmd"
    if lang in FENCE_UNIX:
        return "sh"
    if looks_like_powershell(body):
        return "ps1"
    return "cmd"


def danger_warnings(text: str) -> list[str]:
    low = text.lower()
    found: list[str] = []
    for pattern, label in DANGER_PATTERNS:
        if re.search(pattern, low):
            found.append(label)
    return found


def prepare_command(raw: str) -> CommandPlan | None:
    """Превращает сырой текст из буфера в план выполнения."""
    raw = raw.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not raw:
        return None
    lang, body = strip_code_fences(raw)
    notes: list[str] = []
    if lang:
        notes.append(f"блок кода: {lang or 'без языка'}")

    # Подпись FMR-BRIDGE: выполняем только конверты с верной суммой.
    signed = False
    envelope_issue: str | None = None
    envelope = extract_envelope(body)
    if envelope is not None:
        kind, sha, inner = envelope
        if kind == "out":
            return CommandPlan(text="", dialect="cmd", is_output=True,
                               notes=["это вывод моста (FMR-BRIDGE-OUT), не команда"])
        if kind == "info":
            return CommandPlan(text="", dialect="cmd", is_output=True,
                               notes=["это инструкция моста (FMR-BRIDGE-INFO), не команда"])
        if hash_text(inner) == sha:
            signed = True
            body = normalize_for_hash(inner)
            notes.append("подпись FMR-BRIDGE проверена")
        else:
            envelope_issue = ("контрольная сумма не совпадает: "
                              "текст изменился при копировании или подписан не ассистентом")
    elif "FMR-BRIDGE" in body:
        envelope_issue = "конверт подписи повреждён или не закрыт"

    dialect = classify_command(raw)
    if len(body) > MAX_CLIPBOARD_COMMAND_CHARS:
        body = body[:MAX_CLIPBOARD_COMMAND_CHARS]
        notes.append("текст обрезан: слишком длинный для одной команды")
    return CommandPlan(
        text=body,
        dialect=dialect,
        warnings=danger_warnings(body),
        notes=notes,
        signed=signed,
        envelope_issue=envelope_issue,
    )


def format_preview(text: str, limit: int = 1000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... (ещё {len(text) - limit} символов)"


def plan_gate(plan: CommandPlan, allow_unsigned: bool) -> bool:
    """Решает, можно ли выполнять план.

    Без флага --allow-unsigned выполняются только команды с верной
    подписью FMR-BRIDGE; случайное содержимое буфера игнорируется.
    """
    if plan.is_output:
        print("В буфере — подписанный вывод моста (FMR-BRIDGE-OUT), не команда. Пропускаю.")
        return False
    if plan.signed or allow_unsigned:
        return True
    if plan.envelope_issue:
        print(f"Пропущено: {plan.envelope_issue}.")
    else:
        print("Пропущено: текст без подписи FMR-BRIDGE.")
        print("Скопируйте команду из чата целиком, вместе со строками -----FMR-BRIDGE...-----")
    return False


# ---------------------------------------------------------------------------
# Буфер обмена Windows через ctypes (только стандартная библиотека)
# ---------------------------------------------------------------------------


class WindowsClipboard:
    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        self._user32 = user32
        self._kernel32 = kernel32
        self.CF_UNICODETEXT = 13

        user32.OpenClipboard.argtypes = [wintypes.HWND]
        user32.OpenClipboard.restype = wintypes.BOOL
        user32.CloseClipboard.restype = wintypes.BOOL
        user32.EmptyClipboard.restype = wintypes.BOOL
        user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
        user32.IsClipboardFormatAvailable.restype = wintypes.BOOL
        user32.GetClipboardData.argtypes = [wintypes.UINT]
        user32.GetClipboardData.restype = wintypes.HANDLE
        user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        user32.SetClipboardData.restype = wintypes.HANDLE
        kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
        kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalUnlock.restype = wintypes.BOOL
        kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalFree.restype = wintypes.HGLOBAL

    def read(self) -> str | None:
        ctypes = self._ctypes
        if not self._user32.OpenClipboard(0):
            return None
        try:
            if not self._user32.IsClipboardFormatAvailable(self.CF_UNICODETEXT):
                return None
            handle = self._user32.GetClipboardData(self.CF_UNICODETEXT)
            if not handle:
                return None
            ptr = self._kernel32.GlobalLock(handle)
            if not ptr:
                return None
            try:
                return ctypes.wstring_at(ptr)
            finally:
                self._kernel32.GlobalUnlock(handle)
        finally:
            self._user32.CloseClipboard()

    def write(self, text: str) -> bool:
        ctypes = self._ctypes
        if not self._user32.OpenClipboard(0):
            return False
        try:
            self._user32.EmptyClipboard()
            buf = ctypes.create_unicode_buffer(text + "\0")
            size = ctypes.sizeof(buf)
            gmem_moveable_zeroinit = 0x0042
            handle = self._kernel32.GlobalAlloc(gmem_moveable_zeroinit, size)
            if not handle:
                return False
            ptr = self._kernel32.GlobalLock(handle)
            if not ptr:
                self._kernel32.GlobalFree(handle)
                return False
            ctypes.memmove(ptr, buf, size)
            self._kernel32.GlobalUnlock(handle)
            if not self._user32.SetClipboardData(self.CF_UNICODETEXT, handle):
                self._kernel32.GlobalFree(handle)
                return False
            return True
        finally:
            self._user32.CloseClipboard()


# ---------------------------------------------------------------------------
# Выполнение команд
# ---------------------------------------------------------------------------


class _ConsoleState:
    """Сохраняет и восстанавливает кодовые страницы и шрифт консоли.

    Временные скрипты выполняют `chcp 65001` ради UTF-8 вывода, из-за чего
    классическая консоль Windows может сменить кодовую страницу и шрифт.
    Чтобы окно не «съезжало», после каждой команды возвращаем всё как было.
    """

    def __init__(self) -> None:
        self._ctypes = None
        self._kernel32 = None
        self._handle = None
        self.in_cp: int | None = None
        self.out_cp: int | None = None
        self.font = None

    def save(self) -> None:
        if not sys.platform.startswith("win"):
            return
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            self._ctypes = ctypes
            self._kernel32 = kernel32
            self.in_cp = kernel32.GetConsoleCP()
            self.out_cp = kernel32.GetConsoleOutputCP()

            class COORD(ctypes.Structure):
                _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

            class CONSOLE_FONT_INFOEX(ctypes.Structure):
                _fields_ = [
                    ("cbSize", ctypes.c_ulong),
                    ("nFont", ctypes.c_ulong),
                    ("dwFontSize", COORD),
                    ("FontFamily", ctypes.c_ulong),
                    ("FontWeight", ctypes.c_ulong),
                    ("FaceName", ctypes.c_wchar * 32),
                ]

            self._handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            info = CONSOLE_FONT_INFOEX()
            info.cbSize = ctypes.sizeof(CONSOLE_FONT_INFOEX)
            if kernel32.GetCurrentConsoleFontEx(self._handle, False, ctypes.byref(info)):
                self.font = info
        except Exception:
            self._kernel32 = None
            self.in_cp = self.out_cp = None
            self.font = None

    def restore(self) -> None:
        if self._kernel32 is None:
            return
        try:
            ctypes = self._ctypes
            kernel32 = self._kernel32
            if self.in_cp:
                kernel32.SetConsoleCP(self.in_cp)
            if self.out_cp:
                kernel32.SetConsoleOutputCP(self.out_cp)
            if self.font is not None:
                kernel32.SetCurrentConsoleFontEx(
                    self._handle, False, ctypes.byref(self.font)
                )
        except Exception:
            pass


def build_script_files(plan: CommandPlan, temp_dir: Path) -> tuple[list[str], Path]:
    """Создаёт временный скрипт и возвращает (команда запуска, путь)."""
    import shutil

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    on_windows = sys.platform.startswith("win")
    if plan.dialect == "ps1":
        script = temp_dir / f"bridge_{stamp}.ps1"
        header = (
            "$OutputEncoding = [Console]::OutputEncoding = "
            "[System.Text.Encoding]::UTF8\r\n"
        )
        # UTF-8 с BOM: Windows PowerShell 5.1 иначе прочитает файл как ANSI.
        script.write_text(header + plan.text + "\r\n", encoding="utf-8-sig")
        interpreter = "powershell.exe" if on_windows else (shutil.which("pwsh") or "pwsh")
        argv = [
            interpreter,
            "-NoProfile",
            "-NoLogo",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
        ]
    elif on_windows:
        script = temp_dir / f"bridge_{stamp}.cmd"
        # chcp 65001 до строк с кириллицей: дальше файл читается как UTF-8.
        content = "@echo off\r\nchcp 65001 >nul\r\n" + plan.text.replace("\n", "\r\n") + "\r\n"
        script.write_text(content, encoding="utf-8")
        argv = ["cmd.exe", "/d", "/c", str(script)]
    else:
        # Не Windows: best-effort выполняем "cmd"-команды через sh.
        script = temp_dir / f"bridge_{stamp}.sh"
        script.write_text(plan.text + "\n", encoding="utf-8")
        argv = ["sh", str(script)]
    return argv, script


def run_plan(plan: CommandPlan, cwd: str | None) -> tuple[int, str]:
    """Выполняет план; возвращает (код выхода, накопленный вывод)."""
    temp_dir = Path(tempfile.gettempdir()) / "CmdBridge"
    temp_dir.mkdir(parents=True, exist_ok=True)
    argv, script = build_script_files(plan, temp_dir)
    chunks: list[str] = []
    total = 0
    started = time.monotonic()
    # Команда меняет кодовую страницу консоли (chcp 65001) и иногда шрифт —
    # запоминаем состояние окна и возвращаем его после выполнения.
    state = _ConsoleState()
    state.save()
    try:
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=cwd or None,
            )
        except OSError as exc:
            message = f"Не удалось запустить интерпретатор ({argv[0]}): {exc}\n"
            sys.stdout.write(message)
            log_history(plan, 127, 0.0, len(message))
            return 127, message
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace")
            sys.stdout.write(line)
            sys.stdout.flush()
            if total < MAX_OUTPUT_COPY_CHARS:
                chunks.append(line)
                total += len(line)
        code = proc.wait()
    finally:
        state.restore()
    try:
        script.unlink()
    except OSError:
        pass
    duration = time.monotonic() - started
    output = "".join(chunks)
    if total >= MAX_OUTPUT_COPY_CHARS:
        output += "\n... [вывод обрезан для копирования] ..."
    log_history(plan, code, duration, len(output))
    return code, output


def log_history(plan: CommandPlan, code: int, duration: float, output_len: int) -> None:
    try:
        path = Path(__file__).resolve().parent / HISTORY_NAME
        stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with path.open("a", encoding="utf-8") as fh:
            fh.write(f"[{stamp}] dialect={plan.dialect} exit={code} "
                     f"duration={duration:.1f}s output_chars={output_len}\n")
            fh.write(plan.text.strip() + "\n---\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Интерактивный цикл
# ---------------------------------------------------------------------------

POSITIVE = {"1", "y", "yes", "д", "да", "+"}
NEGATIVE = {"2", "n", "no", "н", "нет", "-"}
EDIT = {"3", "e", "у", "edit"}
QUIT = {"4", "q", "й", "quit", "exit", "выход"}
MENU_LINE = ("1 — выполнить   2 — пропустить   3 — редактировать   "
             "4 — выход   5 — инструкция для ИИ")
IDLE_HINT = "Пока команд нет: 5 — скопировать инструкцию для ИИ, 4 — выход."


def read_key() -> str:
    """Читает одно нажатие клавиши без Enter.

    На Windows — через msvcrt (цифры работают в любой раскладке).
    На остальных системах — запасной вариант через input() с Enter.
    """
    if sys.platform.startswith("win"):
        import msvcrt

        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            # Служебная клавиша (стрелка, F-клавиша): читаем скан-код и
            # сообщаем "пустое" нажатие.
            msvcrt.getwch()
            return ""
        return ch
    try:
        return input("> ").strip()
    except EOFError:
        return "4"


def confirm_and_run(plan: CommandPlan, clipboard, cwd: str | None) -> bool:
    """Показывает команду, спрашивает подтверждение, выполняет.

    Возвращает False, если пользователь попросил выйти.
    """
    print()
    print("=" * 72)
    print("Получена команда из буфера обмена:")
    print("-" * 72)
    print(format_preview(plan.text))
    print("-" * 72)
    if plan.notes:
        print("Примечания: " + "; ".join(plan.notes))
    print(f"Будет выполнено через: {('PowerShell' if plan.dialect == 'ps1' else 'cmd.exe')}"
          + ("  [ВНИМАНИЕ: это Linux/bash-команда, она может не сработать в Windows!]"
             if plan.dialect == "sh" else ""))
    if plan.warnings:
        print()
        print("!! ОПАСНАЯ ОПЕРАЦИЯ. Обнаружено:")
        for w in plan.warnings:
            print(f"   - {w}")
        print("!! Для запуска придётся нажать 1 два раза подряд.")

    while True:
        print()
        print(MENU_LINE)
        print("Нажмите цифру нужного действия — без Enter, раскладка не важна.")
        key = read_key().lower()
        if key in QUIT:
            return False
        if key in NEGATIVE:
            print("Пропущено. Жду следующую команду...")
            return True
        if key in EDIT:
            new_text = edit_in_notepad(plan.text)
            if new_text is None:
                print("Редактор недоступен, команду не меняю.")
                continue
            plan = prepare_command(new_text) or plan
            plan.warnings = danger_warnings(plan.text)
            print("Команда после правки:")
            print(format_preview(plan.text))
            if plan.warnings:
                print("!! Команда помечена как опасная.")
            continue
        if key in {"5", "и", "i"}:
            copy_ai_instructions(clipboard)
            continue
        if key in POSITIVE:
            if plan.warnings:
                print()
                print("!! ОПАСНАЯ ОПЕРАЦИЯ. Нажмите 1 ЕЩЁ РАЗ для запуска,")
                print("!! любую другую клавишу — чтобы отменить.")
                if read_key() != "1":
                    print("Запуск отменён. Возвращаюсь к меню.")
                    continue
            break
        if key in ("", "\r", "\n"):
            continue
        print(f"Не понял клавишу: {key!r}. {MENU_LINE}")

    print("Выполняю...")
    print("=" * 72)
    code, output = run_plan(plan, cwd)
    print()
    print()
    print("=" * 72)
    print(f"Готово, код выхода: {code}")
    print()
    print()
    signed_output = wrap_output(output or "", code)
    if clipboard is not None and clipboard.write(signed_output):
        print("Вывод автоматически скопирован в буфер обмена")
        print("(подписан FMR-BRIDGE-OUT) — вставьте его в чат ассистенту.")
    else:
        print("Не удалось автоматически скопировать вывод в буфер обмена.")
    return True


def edit_in_notepad(text: str) -> str | None:
    if not sys.platform.startswith("win"):
        return None
    fd, path = tempfile.mkstemp(prefix="bridge_edit_", suffix=".txt", text=False)
    os.close(fd)
    try:
        Path(path).write_text(text, encoding="utf-8")
        subprocess.run(["notepad.exe", path], check=False)
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return None
    finally:
        try:
            Path(path).unlink()
        except OSError:
            pass


def run_clipboard_monitor(args: argparse.Namespace, clipboard) -> int:
    print("Слежу за буфером обмена. Скопируйте команду из чата — я подхвачу её сам.")
    print(IDLE_HINT)
    on_windows = sys.platform.startswith("win")
    if on_windows:
        import msvcrt
    last_seen: str | None = None
    try:
        while True:
            if on_windows:
                # Пока команд нет, можно нажать клавиши прямо в окне.
                while msvcrt.kbhit():
                    key = read_key().lower()
                    if key in {"5", "и", "i"}:
                        copy_ai_instructions(clipboard)
                    elif key in QUIT:
                        print("\nВыход. Пока!")
                        return 0
                    elif key in ("", "\r", "\n"):
                        continue
                    else:
                        print(IDLE_HINT)
            try:
                text = clipboard.read()
            except Exception:
                text = None
            if text is None or text.strip() == "" or text == last_seen:
                time.sleep(POLL_SECONDS)
                continue
            last_seen = text
            plan = prepare_command(text)
            if plan is None:
                continue
            if not plan_gate(plan, args.allow_unsigned):
                continue
            if not confirm_and_run(plan, clipboard, args.dir):
                return 0
            if args.once:
                return 0
    except KeyboardInterrupt:
        print("\nВыход. Пока!")
        return 0


def run_paste_mode(args: argparse.Namespace) -> int:
    print("Режим ручного ввода (не Windows): вставьте команду и завершите пустой строкой.")
    while True:
        print()
        lines: list[str] = []
        try:
            first = input("Команда (пустая строка = конец, 'й'/'q' = выход) > ")
        except (EOFError, KeyboardInterrupt):
            print("\nВыход. Пока!")
            return 0
        if first.strip().lower() in QUIT:
            return 0
        if first.strip().lower() in {"5", "и", "i", "инструкция", "instruction"}:
            copy_ai_instructions(None)
            continue
        lines.append(first)
        while True:
            try:
                line = input("> ")
            except EOFError:
                break
            if line.strip() == "":
                break
            lines.append(line)
        text = "\n".join(lines)
        plan = prepare_command(text)
        if plan is None:
            continue
        if not plan_gate(plan, args.allow_unsigned):
            continue
        if not confirm_and_run(plan, None, args.dir):
            return 0
        if args.once:
            return 0


def banner() -> None:
    print("=" * 72)
    print(APP_TITLE)
    print("Команды из чата -> буфер обмена -> это окно -> ваш подтверждённый запуск.")
    print("Принимаются только команды с подписью -----FMR-BRIDGE...----- от ассистента;")
    print("вывод каждой команды автоматически копируется обратно с подписью")
    print("-----FMR-BRIDGE-OUT-----. Клавиша 5 копирует инструкцию для другой")
    print("модели/агента о том, как общаться через этот мост.")
    print("=" * 72)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=APP_TITLE)
    parser.add_argument("--dir", help="рабочая папка для выполнения команд")
    parser.add_argument("--once", action="store_true",
                        help="выполнить одну команду и выйти")
    parser.add_argument("--text", help="выполнить указанную команду (минуя буфер обмена)")
    parser.add_argument("--allow-unsigned", action="store_true",
                        help="разрешить выполнение команд без подписи FMR-BRIDGE")
    args = parser.parse_args(argv)

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

    banner()

    if args.dir and not Path(args.dir).is_dir():
        print(f"Папка не найдена: {args.dir}")
        return 2

    if sys.platform.startswith("win"):
        import ctypes

        try:
            ctypes.windll.kernel32.SetConsoleTitleW(APP_TITLE)  # type: ignore[attr-defined]
        except Exception:
            pass
        clipboard = WindowsClipboard()

        if args.text is not None:
            plan = prepare_command(args.text)
            if plan is None:
                print("Пустая команда.")
                return 2
            return 0 if confirm_and_run(plan, clipboard, args.dir) else 1
        return run_clipboard_monitor(args, clipboard)

    print("(Windows не обнаружен — буфер обмена недоступен.)")
    if args.text is not None:
        plan = prepare_command(args.text)
        if plan is None:
            print("Пустая команда.")
            return 2
        return 0 if confirm_and_run(plan, None, args.dir) else 1
    return run_paste_mode(args)


if __name__ == "__main__":
    raise SystemExit(main())
