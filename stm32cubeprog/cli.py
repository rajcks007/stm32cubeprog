"""
import subprocess
import os

cli_path = "C:\\Program Files\\STMicroelectronics\\STM32Cube\\STM32CubeProgrammer\\bin\\STM32_Programmer_CLI.exe"
firmware = "C:\\Users\\rchoksi\\Project\\logger.bin"

if not os.path.isfile(cli_path):
    raise FileNotFoundError(f"CLI not found: {cli_path}")

if not os.path.isfile(firmware):
    raise FileNotFoundError(f"Firmware not found: {firmware}")

cmd = [
    cli_path,
    "-c", "port=SWD", "freq=4000",                      # -c = connect options (e.g., SWD, USB, UART)
    "-w", firmware, "0x08000000",                       # -w = write firmware to flash at specified address, 0x08000000 = start address in flash
    "-v", "-rst"                                        # -v = verify after writing, -rst = reset after programming
]

try:
    result = subprocess.run(cmd, capture_output=True, text=True)
    print("STDOUT:", result.stdout)
    print("STDERR:", result.stderr)
except FileNotFoundError:
    print(f"File not found when trying to execute: {cmd[0]}")
    raise
"""

from __future__ import annotations                          # noqa: E402
import os                                                   # noqa: E402
import sys                                                  # noqa: E402
import shlex                                                # noqa: E402
import platform                                             # noqa: E402
import subprocess                                           # noqa: E402
from dataclasses import dataclass                           # noqa: E402
from typing import List, Optional, Tuple, Iterable          # noqa: E402
from pathlib import Path                                    # noqa: E402
import re                                                   # noqa: E402
import threading                                            # noqa: E402
from typing import Callable                                 # noqa: E402


class CubeProgError(Exception):
    """Raised when the STM32CubeProgrammer CLI returns an error."""


@dataclass
class ConnectOptions:
    """
    Connection options passed to '-c'.
    Provide whichever make sense for your setup.

    Common examples:
        port="SWD", freq=4000
        port="JTAG", freq=15000
        port="USB1"               (DFU)
        port="UART1", baud=115200, parity="even"
    """
    port: Optional[str] = None
    freq: Optional[int] = None           # kHz for SWD/JTAG
    mode: Optional[str] = None           # hotplug, underreset, etc.
    reset: Optional[str] = None          # swrst, hwrst
    index: Optional[int] = None          # ST-LINK index when multiple
    sn: Optional[str] = None             # probe serial number
    # UART options
    baud: Optional[int] = None
    parity: Optional[str] = None
    stopbits: Optional[int] = None

    def to_args(self) -> List[str]:
        parts: List[str] = []
        if self.port:       parts.append(f"port={self.port}")                   # noqa: E701
        if self.freq:       parts.append(f"freq={self.freq}")                   # noqa: E701
        if self.mode:       parts.append(f"mode={self.mode}")                   # noqa: E701
        if self.reset:      parts.append(f"reset={self.reset}")                 # noqa: E701
        if self.index is not None: parts.append(f"index={self.index}")          # noqa: E701
        if self.sn:         parts.append(f"sn={self.sn}")                       # noqa: E701
        if self.baud:       parts.append(f"baud={self.baud}")                   # noqa: E701
        if self.parity:     parts.append(f"parity={self.parity}")               # noqa: E701
        if self.stopbits:   parts.append(f"stopbit={self.stopbits}")            # noqa: E701
        if not parts:
            return []
        return ["-c"] + parts


def _dedupe(seq: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for s in seq:
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _windows_registry_paths(exe_name: str) -> List[str]:
    """Find STM32CubeProgrammer via Windows uninstall registry."""
    paths: List[str] = []
    try:
        import winreg
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for subkey in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                           r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"):
                try:
                    with winreg.OpenKey(hive, subkey) as k:
                        for i in range(0, winreg.QueryInfoKey(k)[0]):
                            try:
                                sk_name = winreg.EnumKey(k, i)
                                with winreg.OpenKey(k, sk_name) as sk:
                                    try:
                                        disp, _ = winreg.QueryValueEx(sk, "DisplayName")
                                    except FileNotFoundError:
                                        continue
                                    if "STM32CubeProgrammer" in disp or "STM32CubeProgrammer" in disp:
                                        # Prefer InstallLocation, else DisplayIcon
                                        install = None
                                        for val in ("InstallLocation", "DisplayIcon"):
                                            try:
                                                v, _ = winreg.QueryValueEx(sk, val)
                                                if v:
                                                    install = v
                                                    break
                                            except FileNotFoundError:
                                                pass
                                        if install:
                                            p = Path(install)
                                            # If a directory, join exe; if file, use parent
                                            if p.is_dir():
                                                candidate = p / "bin" / exe_name
                                            else:
                                                candidate = p
                                                if candidate.name.lower() != exe_name.lower():
                                                    candidate = candidate.parent / exe_name
                                            paths.append(str(candidate))
                            except OSError:
                                continue
                except FileNotFoundError:
                    continue
    except Exception:
        # Any registry access issue: just ignore and continue with other methods
        pass
    return paths


def _rglob_candidates(bases: Iterable[str], exe_name: str, limit: int = 12) -> List[str]:
    """Search a few possible directories recursively for the CLI."""
    found: List[str] = []
    for base in bases:
        if not base:
            continue
        p = Path(base)
        if not p.exists():
            continue
        try:
            for hit in p.rglob(exe_name):
                found.append(str(hit))
                if len(found) >= limit:
                    return found
        except (PermissionError, OSError):
            continue
    return found


def default_cli_candidates(extra_dirs: Optional[Iterable[str]] = None) -> List[str]:
    """
    Return likely locations of STM32_Programmer_CLI across OSes.
    - Respects env vars: STM32CUBEPRG_CLI or STM32CUBEPROG_CLI
    - Checks common install paths
    - On Windows, queries the Registry
    - Recursively searches user + system locations
    - Finally adds bare name for PATH lookup
    """
    env_override = os.environ.get("STM32CUBEPRG_CLI") or os.environ.get("STM32CUBEPROG_CLI")
    if env_override:
        return [env_override]

    system = platform.system().lower()
    is_windows = "windows" in system
    exe_name = "STM32_Programmer_CLI.exe" if is_windows else "STM32_Programmer_CLI"

    candidates: List[str] = []

    # 1) Common install paths
    if is_windows:
        candidates += [
            r"C:\Program Files\STMicroelectronics\STM32Cube\STM32CubeProgrammer\bin\STM32_Programmer_CLI.exe",
            r"C:\Program Files\STMicroelectronics\STM32CubeProgrammer\bin\STM32_Programmer_CLI.exe",
            r"C:\Program Files (x86)\STMicroelectronics\STM32Cube\STM32CubeProgrammer\bin\STM32_Programmer_CLI.exe",
            r"C:\Program Files (x86)\STMicroelectronics\STM32CubeProgrammer\bin\STM32_Programmer_CLI.exe",
        ]
        # 2) Windows Registry lookup
        candidates += _windows_registry_paths(exe_name)

        # 3) Recursive search in likely roots (user + system)
        search_roots = [
            os.environ.get("ProgramFiles"),
            os.environ.get("ProgramFiles(x86)"),
            os.environ.get("ProgramData"),
            os.environ.get("LOCALAPPDATA"),
            os.environ.get("USERPROFILE"),
        ]
        if extra_dirs:
            search_roots += list(extra_dirs)
        candidates += _rglob_candidates(search_roots, exe_name, limit=12)

    else:
        # Linux/macOS typical paths
        candidates += [
            "/usr/local/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI",
            "/usr/local/STMicroelectronics/STM32CubeProgrammer/bin/STM32_Programmer_CLI",
            "/opt/STMicroelectronics/STM32CubeProgrammer/bin/STM32_Programmer_CLI",
            "/usr/bin/STM32_Programmer_CLI",
            "/usr/local/bin/STM32_Programmer_CLI",
            # macOS – sometimes under Applications or user-local installs
            "/Applications/STMicroelectronics/STM32CubeProgrammer/STM32CubeProgrammer.app/Contents/MacOS/bin/STM32_Programmer_CLI",
            "/Applications/STM32CubeProgrammer.app/Contents/MacOS/bin/STM32_Programmer_CLI",
        ]

        # Recursive search in likely roots
        search_roots = [
            "/usr/local",
            "/opt",
            str(Path.home()),
            "/Applications",  # macOS
        ]
        if extra_dirs:
            search_roots += list(extra_dirs)
        candidates += _rglob_candidates(search_roots, exe_name, limit=12)

    # 4) PATH fallback (let shutil.which find it)
    candidates.append(exe_name)

    return _dedupe(candidates)


def _which(exe: str) -> Optional[str]:
    """Return absolute path if executable is found, otherwise None."""
    if os.path.isabs(exe) and os.path.exists(exe):
        return exe
    from shutil import which
    return which(exe)


class CubeProgCLI:
    def __init__(self, cli_path: Optional[str] = None, default_timeout: int = 300):
        self.cli_path = self._resolve_cli(cli_path)
        self.default_timeout = default_timeout

    @staticmethod
    def _resolve_cli(cli_path: Optional[str]) -> str:
        """
        Resolve the STM32_Programmer_CLI path by:
        1) honoring an explicit cli_path if given,
        2) iterating the enhanced default_cli_candidates(),
        3) failing with a helpful error.
        """
        # 1) Explicit path
        if cli_path:
            found = _which(cli_path)
            if not found:
                raise FileNotFoundError(f"STM32_Programmer_CLI not found at: {cli_path}")
            return found

        # 2) Try all candidates (env override, registry, common paths, recursive search, PATH)
        for cand in default_cli_candidates():
            found = _which(cand)
            if found:
                return found

        # 3) Give a clear error
        raise FileNotFoundError(
            "STM32_Programmer_CLI not found. "
            "Install STM32CubeProgrammer, add it to your PATH, set STM32CUBEPRG_CLI, "
            "or pass cli_path explicitly."
        )

    def _run(
        self,
        args: List[str],
        timeout: Optional[int] = None,
        live: bool = False
    ) -> Tuple[int, str, str]:
        """
        Run CLI with given args. If live=True, stream output to console.
        Returns (returncode, stdout, stderr). Raises CubeProgError on nonzero return.
        """
        cmd = [self.cli_path] + args

        if live:
            # Stream output line by line
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            out_lines: List[str] = []
            err_lines: List[str] = []
            try:
                assert process.stdout is not None
                assert process.stderr is not None
                for line in iter(process.stdout.readline, ""):
                    print(line, end="")
                    out_lines.append(line)
                # After stdout completes, read remaining stderr
                err = process.stderr.read()
                if err:
                    print(err, end="", file=sys.stderr)
                    err_lines.append(err)
                rc = process.wait(timeout=timeout or self.default_timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                raise CubeProgError("STM32_Programmer_CLI timed out.")
            stdout = "".join(out_lines)
            stderr = "".join(err_lines)
        else:
            try:
                cp = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout or self.default_timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                raise CubeProgError("STM32_Programmer_CLI timed out.")
            rc, stdout, stderr = cp.returncode, cp.stdout, cp.stderr

        if rc != 0:
            raise CubeProgError(self._format_cli_error(cmd, rc, stdout, stderr))
        return rc, stdout, stderr

    @staticmethod
    def _format_cli_error(cmd: Iterable[str], rc: int, out: str, err: str) -> str:
        return (
            "STM32_Programmer_CLI failed.\n"
            f"Command: {shlex.join(cmd)}\n"
            f"Return code: {rc}\n"
            f"--- STDOUT ---\n{out}\n"
            f"--- STDERR ---\n{err}\n"
        )

    # ----------------------
    # Public helper methods
    # ----------------------

    def get_version(self) -> str:
        """Return CLI version string."""
        _, out, _ = self._run(["-v"])
        # CLI prints a banner; try to grab the version line.
        for line in out.splitlines():
            if "STM32CubeProgrammer" in line and "version" in line.lower():
                return line.strip()
        return out.strip() or "Unknown version"

    def list_probes(self) -> str:
        """List connected ST-LINK/ports (raw CLI output)."""
        _, out, _ = self._run(["-l", "port=SWD"])
        return out

    def _connect_args(self, **kwargs) -> List[str]:
        """
        Build '-c' arguments from kwargs or a ConnectOptions.
        Accepts either:
            _connect_args(port="SWD", freq=4000)
        or:
            _connect_args(options=ConnectOptions(...))
        """
        if "options" in kwargs and isinstance(kwargs["options"], ConnectOptions):
            return kwargs["options"].to_args()

        # Map kwargs to ConnectOptions
        co = ConnectOptions(
            port=kwargs.get("port"),
            freq=kwargs.get("freq"),
            mode=kwargs.get("mode"),
            reset=kwargs.get("reset_mode") or kwargs.get("reset"),
            index=kwargs.get("index"),
            sn=kwargs.get("sn"),
            baud=kwargs.get("baud"),
            parity=kwargs.get("parity"),
            stopbits=kwargs.get("stopbits"),
        )
        return co.to_args()

    def flash_firmware(
        self,
        file_path: str,
        address: int,
        verify: bool = True,
        reset: bool = True,
        file_type: Optional[str] = None,
        timeout: Optional[int] = None,
        live: bool = True,  # kept for compatibility; when True we stream
        on_progress: Optional[Callable[[int, str], None]] = None,
        on_log: Optional[Callable[[str, str], None]] = None,
        **connect_kwargs,
    ) -> None:
        """
        Flash a binary/hex/elf to the target at given address.
        Callbacks:
          - on_progress(percentage:int, line:str)
          - on_log(stream:str, line:str) where stream is "stdout" or "stderr"
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(file_path)

        args: List[str] = []
        args += self._connect_args(**connect_kwargs)
        args += ["-w", file_path, f"0x{address:08X}"]
        if file_type:
            args += [f"type={file_type}"]
        if verify:
            args.append("-v")
        if reset:
            args.append("-rst")

        if live or on_progress or on_log:
            # Use streaming mode (gives us real-time progress)
            self._run_streaming(args, timeout=timeout, on_progress=on_progress, on_log=on_log)
        else:
            # Fallback to buffered mode
            self._run(args, timeout=timeout, live=False)

    def read_memory(
        self,
        address: int,
        size: int,
        out_file: str,
        file_type: str = "bin",
        timeout: Optional[int] = None,
        live: bool = False,
        **connect_kwargs
    ) -> None:
        """
        Read memory to a file.
        file_type: "bin" or "hex"
        """
        args: List[str] = []
        args += self._connect_args(**connect_kwargs)
        args += ["-r", f"0x{address:08X}", f"{size}", out_file, f"type={file_type}"]
        self._run(args, timeout=timeout, live=live)

    def erase(
        self,
        scope: str = "all",
        bank: Optional[int] = None,
        sector: Optional[int] = None,
        timeout: Optional[int] = None,
        live: bool = True,
        **connect_kwargs
    ) -> None:
        """
        Erase flash.
        scope: "all" | "bank" | "sector"
        Provide bank/sector numbers when needed.
        """
        args: List[str] = []
        args += self._connect_args(**connect_kwargs)

        if scope == "all":
            args += ["-e", "all"]
        elif scope == "bank" and bank is not None:
            args += ["-e", f"bank={bank}"]
        elif scope == "sector" and sector is not None:
            args += ["-e", f"sector={sector}"]
        else:
            raise ValueError("Invalid erase parameters.")

        self._run(args, timeout=timeout, live=live)

    def reset(
        self,
        sw: bool = True,
        timeout: Optional[int] = None,
        live: bool = False,
        **connect_kwargs
    ) -> None:
        """Reset target (software reset by default)."""
        args: List[str] = []
        args += self._connect_args(**connect_kwargs)
        args += ["-rst"] if sw else ["-hardrst"]
        self._run(args, timeout=timeout, live=live)

    def read_device_info(
        self,
        timeout: Optional[int] = None,
        live: bool = False,
        **connect_kwargs
    ) -> str:
        """Read device info / option bytes (raw CLI output)."""
        args: List[str] = []
        args += self._connect_args(**connect_kwargs)
        args += ["-i"]
        _, out, _ = self._run(args, timeout=timeout, live=live)
        return out

    def write_option_bytes(
        self,
        kv_pairs: List[str],
        timeout: Optional[int] = None,
        live: bool = True,
        **connect_kwargs
    ) -> None:
        """
        Write option bytes.
        kv_pairs: e.g. ["nWRP=0x0", "RDP=0xAA"]
        """
        if not kv_pairs:
            raise ValueError("kv_pairs cannot be empty.")
        args: List[str] = []
        args += self._connect_args(**connect_kwargs)
        args += ["-ob"] + kv_pairs
        self._run(args, timeout=timeout, live=live)

    def set_rdp(
        self,
        level: str,
        timeout: Optional[int] = None,
        live: bool = True,
        **connect_kwargs
    ) -> None:
        """
        Convenience for setting Readout Protection.
        level: "0" | "1" | "2"
        """
        level_map = {"0": "AA", "1": "55", "2": "CC"}
        if level not in level_map:
            raise ValueError("RDP level must be '0', '1', or '2'.")
        self.write_option_bytes([f"RDP=0x{level_map[level]}"], timeout=timeout, live=live, **connect_kwargs)

    _ANY_PCT = re.compile(r"(\d{1,3})\s*%")  # matches 0%..100% and '100 %'

    def _run_streaming(
        self,
        args: list[str],
        timeout: Optional[int] = None,
        on_progress: Optional[Callable[[int, str], None]] = None,
        on_log: Optional[Callable[[str, str], None]] = None,  # "stdout"|"stderr"
    ) -> int:
        cmd = [self.cli_path] + args
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # line buffered
            )
        except FileNotFoundError:
            raise FileNotFoundError(f"Cannot execute: {cmd[0]}")

        stdout_done = threading.Event()
        stderr_done = threading.Event()

        phase = None  # "download" | "verify" | None
        last_pct = {"download": -1, "verify": -1}

        def maybe_progress(line: str):
            nonlocal phase
            low = line.lower()

            # detect phase start/end
            if "download in progress" in low:
                phase = "download"
                return
            if "read progress" in low:
                phase = "verify"
                return
            if "file download complete" in low or "download verified successfully" in low:
                phase = None
                return

            # parse percentages if inside a known phase
            if phase in ("download", "verify"):
                matches = self._ANY_PCT.findall(line)
                if matches:
                    pct = int(matches[-1])                # last % in the line
                    pct = max(0, min(100, pct))           # clamp 0..100
                    if pct != last_pct[phase]:
                        last_pct[phase] = pct
                        if on_progress:
                            try:
                                on_progress(pct, line)
                            except Exception:
                                pass

        def _pump(stream, name):
            try:
                assert stream is not None
                for raw in stream:
                    line = raw.rstrip("\n")

                    # detect & emit progress (keeps your custom bar accurate)
                    maybe_progress(line)

                    # Filter out STM32_Programmer_CLI's built-in progress lines
                    if "%" in line:
                        continue  # skip built-in percentage output

                    # 1) Print live to console
                    print(line, flush=True)

                    # 2) Call per-line log callback
                    if on_log:
                        try:
                            on_log(name, line)
                        except Exception:
                            pass

            finally:
                (stdout_done if name == "stdout" else stderr_done).set()

        # Start threads for stdout and stderr
        t_out = threading.Thread(target=_pump, args=(proc.stdout, "stdout"), daemon=True)
        t_err = threading.Thread(target=_pump, args=(proc.stderr, "stderr"), daemon=True)
        t_out.start()
        t_err.start()

        try:
            rc = proc.wait(timeout=timeout or self.default_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise CubeProgError("STM32_Programmer_CLI timed out.")

        stdout_done.wait(1.0)
        stderr_done.wait(1.0)

        if rc != 0:
            raise CubeProgError("STM32_Programmer_CLI failed (see live output above).")
        return rc


# ----------------------
# Script usage example
# ----------------------
def main():
    import argparse

    parser = argparse.ArgumentParser(description="Python wrapper for STM32CubeProgrammer CLI")
    parser.add_argument("--cli", help="Path to STM32_Programmer_CLI (optional).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ver = sub.add_parser("version", help="Show CLI version")

    p_list = sub.add_parser("list", help="List probes/ports")

    p_flash = sub.add_parser("flash", help="Flash firmware to address")
    p_flash.add_argument("file")
    p_flash.add_argument("address", type=lambda x: int(x, 0))
    p_flash.add_argument("--no-verify", action="store_true")
    p_flash.add_argument("--no-reset", action="store_true")
    p_flash.add_argument("--type", choices=["bin", "hex", "elf"])

    p_read = sub.add_parser("read", help="Read memory to file")
    p_read.add_argument("address", type=lambda x: int(x, 0))
    p_read.add_argument("size", type=lambda x: int(x, 0))
    p_read.add_argument("out")
    p_read.add_argument("--type", choices=["bin", "hex"], default="bin")

    p_erase = sub.add_parser("erase", help="Erase flash")
    p_erase.add_argument("scope", choices=["all", "bank", "sector"])
    p_erase.add_argument("--bank", type=int)
    p_erase.add_argument("--sector", type=int)

    p_reset = sub.add_parser("reset", help="Reset target")
    p_reset.add_argument("--hard", action="store_true")

    p_info = sub.add_parser("info", help="Read device info/option bytes")

    p_ob = sub.add_parser("ob", help="Write option bytes")
    p_ob.add_argument("kv", nargs="+", help='Key/Value pairs like RDP=0xAA nWRP=0x0 ...')

    p_rdp = sub.add_parser("rdp", help="Set Readout Protection level")
    p_rdp.add_argument("level", choices=["0", "1", "2"])

    # Common connect args
    for sp in (p_flash, p_read, p_erase, p_reset, p_info, p_ob, p_rdp, p_list):
        sp.add_argument("--port", help="SWD|JTAG|USBx|UARTx, etc.")
        sp.add_argument("--freq", type=int, help="kHz for SWD/JTAG")
        sp.add_argument("--mode", help="hotplug|underreset|...")
        sp.add_argument("--reset-mode", help="swrst|hwrst")
        sp.add_argument("--index", type=int, help="Probe index when multiple")
        sp.add_argument("--sn", help="Probe serial number")
        sp.add_argument("--baud", type=int, help="UART baud")
        sp.add_argument("--parity", help="UART parity")
        sp.add_argument("--stopbits", type=int, help="UART stop bits")
        sp.add_argument("--timeout", type=int, help="Seconds to wait (default 300)")
        sp.add_argument("--no-live", action="store_true", help="Disable live console output")

    args = parser.parse_args()
    prog = CubeProgCLI(cli_path=args.cli)

    try:
        if args.cmd == "version":
            print(prog.get_version())

        elif args.cmd == "list":
            out = prog.list_probes()
            print(out)

        elif args.cmd == "flash":
            def _cb_progress(pct, line):
                width = 30
                bar = "#" * int(pct/100*width)
                sys.stdout.write(f"\r[{bar:<30}] {pct:3d}%")
                sys.stdout.flush()
                if pct >= 100:
                    sys.stdout.write("\n")
            prog.flash_firmware(
                args.file,
                address=args.address,
                verify=not args.no_verify,
                reset=not args.no_reset,
                file_type=args.type,
                timeout=args.timeout,
                live=True,
                on_progress=_cb_progress,
                port=args.port,
                freq=args.freq,
                mode=args.mode,
                reset_mode=args.reset_mode,
                index=args.index,
                sn=args.sn,
                baud=args.baud,
                parity=args.parity,
                stopbits=args.stopbits,
            )

        elif args.cmd == "read":
            prog.read_memory(
                address=args.address,
                size=args.size,
                out_file=args.out,
                file_type=args.type,
                timeout=args.timeout,
                live=not args.no_live,
                port=args.port,
                freq=args.freq,
                mode=args.mode,
                reset_mode=args.reset_mode,
                index=args.index,
                sn=args.sn,
                baud=args.baud,
                parity=args.parity,
                stopbits=args.stopbits,
            )

        elif args.cmd == "erase":
            prog.erase(
                scope=args.scope,
                bank=args.bank,
                sector=args.sector,
                timeout=args.timeout,
                live=not args.no_live,
                port=args.port,
                freq=args.freq,
                mode=args.mode,
                reset_mode=args.reset_mode,
                index=args.index,
                sn=args.sn,
                baud=args.baud,
                parity=args.parity,
                stopbits=args.stopbits,
            )

        elif args.cmd == "reset":
            prog.reset(
                sw=not args.hard,
                timeout=args.timeout,
                live=not args.no_live,
                port=args.port,
                freq=args.freq,
                mode=args.mode,
                reset_mode=args.reset_mode,
                index=args.index,
                sn=args.sn,
                baud=args.baud,
                parity=args.parity,
                stopbits=args.stopbits,
            )

        elif args.cmd == "info":
            out = prog.read_device_info(
                timeout=args.timeout,
                live=not args.no_live,
                port=args.port,
                freq=args.freq,
                mode=args.mode,
                reset_mode=args.reset_mode,
                index=args.index,
                sn=args.sn,
                baud=args.baud,
                parity=args.parity,
                stopbits=args.stopbits,
            )
            print(out)

        elif args.cmd == "ob":
            prog.write_option_bytes(
                kv_pairs=args.kv,
                timeout=args.timeout,
                live=not args.no_live,
                port=args.port,
                freq=args.freq,
                mode=args.mode,
                reset_mode=args.reset_mode,
                index=args.index,
                sn=args.sn,
                baud=args.baud,
                parity=args.parity,
                stopbits=args.stopbits,
            )

        elif args.cmd == "rdp":
            prog.set_rdp(
                level=args.level,
                timeout=args.timeout,
                live=not args.no_live,
                port=args.port,
                freq=args.freq,
                mode=args.mode,
                reset_mode=args.reset_mode,
                index=args.index,
                sn=args.sn,
                baud=args.baud,
                parity=args.parity,
                stopbits=args.stopbits,
            )

    except CubeProgError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()  # pragma: no cover
