"""Client for cv3inx/turnstile-solver ("Violetics Solver") with Built-In Camoufox Local Solver Fallback."""
import asyncio
import contextlib
import glob
import html
import logging
import os
import random
import re
import shutil
import subprocess
import sys
import time
from typing import Optional

import aiohttp

log = logging.getLogger("g2s.solver")


class SolverError(Exception):
    pass


_GLOBAL_SOLVER_SEM = asyncio.Semaphore(int(os.environ.get("G2S_SOLVER_CONCURRENCY", "50")))
_GLOBAL_START_LOCK = asyncio.Lock()
_GLOBAL_LAST_SOLVE = 0.0
_GLOBAL_REMOTE_UNAUTH_UNTIL = 0.0

_HOST_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>.</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onloadTurnstileCallback" async defer></script>
</head>
<body>
__WIDGET__
<p id="ip-display"></p>
</body>
</html>"""

_DEAD_BROWSER_HINTS = (
    "connection closed",
    "browser has been closed",
    "target page, context or browser has been closed",
    "browser context has been closed",
    "epipe",
)


def _attr(v: str) -> str:
    return html.escape(str(v), quote=True)


def sanitize_turnstile_action(action: Optional[str]) -> Optional[str]:
    if not action:
        return None
    action_str = str(action).strip()
    if not action_str:
        return None
    if re.match(r"^[A-Za-z0-9_-]{1,32}$", action_str):
        return action_str
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "_", action_str)[:32]
    return cleaned or None


def _ensure_xvfb_and_env() -> None:
    """Ensure LD_LIBRARY_PATH includes Camoufox/system libs and Xvfb is running on DISPLAY."""
    extra_lib_dirs = []
    for pattern in (
        "/home/user/.cache/camoufox/browsers/official/*",
        "/root/.cache/camoufox/browsers/official/*",
        "/tmp/libs/usr/lib/x86_64-linux-gnu",
        "/tmp/libs/lib/x86_64-linux-gnu",
    ):
        for p in glob.glob(pattern):
            if os.path.isdir(p) and p not in extra_lib_dirs:
                extra_lib_dirs.append(p)
    if extra_lib_dirs:
        cur_ld = os.environ.get("LD_LIBRARY_PATH", "")
        cur_parts = [x for x in cur_ld.split(":") if x]
        merged = extra_lib_dirs + [x for x in cur_parts if x not in extra_lib_dirs]
        os.environ["LD_LIBRARY_PATH"] = ":".join(merged)

    disp = os.environ.get("DISPLAY", "").strip()
    if not disp:
        disp = ":99"
        os.environ["DISPLAY"] = disp

    disp_num = disp.lstrip(":").split(".")[0]
    x_sock = f"/tmp/.X11-unix/X{disp_num}"

    def _is_x_alive(sock_path: str) -> bool:
        if not os.path.exists(sock_path):
            return False
        import socket as _sock
        s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            s.connect(sock_path)
            return True
        except Exception:
            return False
        finally:
            try:
                s.close()
            except Exception:
                pass

    if _is_x_alive(x_sock):
        return

    if os.path.exists("/tmp/libs/usr/bin/xkbcomp") and not os.path.exists("/usr/bin/xkbcomp"):
        try:
            os.makedirs("/tmp/bin", exist_ok=True)
            os.makedirs("/tmp/lib/xkb", exist_ok=True)
            xkb_wrap = "/tmp/bin/xkbcomp"
            if not os.path.exists(xkb_wrap):
                with open(xkb_wrap, "w", encoding="utf-8") as wf:
                    wf.write(
                        "#!/bin/sh\n"
                        'export LD_LIBRARY_PATH="/tmp/libs/usr/lib/x86_64-linux-gnu:/tmp/libs/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH"\n'
                        'exec /tmp/libs/usr/bin/xkbcomp -I/tmp/libs/usr/share/X11/xkb "$@"\n'
                    )
                os.chmod(xkb_wrap, 0o755)
            xvfb_tmp = "/tmp/libs/usr/bin/Xvfb"
            if os.path.exists(xvfb_tmp):
                with open(xvfb_tmp, "rb") as rf:
                    raw_xvfb = rf.read()
                if b"/usr/bin\x00" in raw_xvfb or b"/var/lib/xkb/" in raw_xvfb:
                    raw_xvfb = raw_xvfb.replace(b"/usr/bin\x00", b"/tmp/bin\x00").replace(
                        b"/var/lib/xkb/", b"/tmp/lib/xkb/"
                    )
                    with open(xvfb_tmp, "wb") as wf:
                        wf.write(raw_xvfb)
                    os.chmod(xvfb_tmp, 0o755)
        except Exception:
            pass

    if os.path.isdir("/tmp/bin"):
        cur_path = os.environ.get("PATH", "")
        if "/tmp/bin" not in cur_path.split(":"):
            os.environ["PATH"] = f"/tmp/bin:{cur_path}" if cur_path else "/tmp/bin"

    xvfb_bin = (
        shutil.which("Xvfb")
        or ("/tmp/bin/Xvfb" if os.path.exists("/tmp/bin/Xvfb") else None)
        or ("/tmp/libs/usr/bin/Xvfb" if os.path.exists("/tmp/libs/usr/bin/Xvfb") else None)
    )
    if not xvfb_bin:
        return
    try:
        for stale_p in (f"/tmp/.X{disp_num}-lock", x_sock):
            if os.path.lexists(stale_p):
                try:
                    os.unlink(stale_p)
                except Exception:
                    pass
        cmd = [
            xvfb_bin,
            disp,
            "-screen",
            "0",
            "1280x720x24",
            "-ac",
            "+extension",
            "GLX",
            "+render",
            "-noreset",
        ]
        if os.path.isdir("/tmp/libs/usr/share/X11/xkb") and not os.path.isdir("/usr/share/X11/xkb"):
            cmd.extend(["-xkbdir", "/tmp/libs/usr/share/X11/xkb"])
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=os.environ.copy(),
            start_new_session=True,
        )
        for _ in range(30):
            if _is_x_alive(x_sock):
                break
            time.sleep(0.1)
    except Exception as e:
        log.warning("Failed to start Xvfb on %s: %s", disp, e)


class _LocalCamoufoxSolver:
    """In-process Camoufox (stealth Firefox under Xvfb) Turnstile solver."""

    def __init__(self, max_concurrent: int = 12):
        self._camoufox = None
        self.browser = None
        self.sem = asyncio.Semaphore(max_concurrent)
        self._key_locks: dict[str, asyncio.Lock] = {}
        self._key_refs: dict[str, int] = {}
        self._start_lock = asyncio.Lock()
        self.solve_count = 0
        self.stopped = False
        self.generation = 0
        self._loop = None

    @contextlib.asynccontextmanager
    async def keyed(self, key: str):
        lock = self._key_locks.setdefault(key, asyncio.Lock())
        self._key_refs[key] = self._key_refs.get(key, 0) + 1
        try:
            async with lock:
                yield
        finally:
            self._key_refs[key] = self._key_refs.get(key, 1) - 1
            if self._key_refs[key] <= 0:
                self._key_refs.pop(key, None)
                self._key_locks.pop(key, None)

    def _is_alive(self) -> bool:
        try:
            cur_loop = asyncio.get_running_loop()
        except RuntimeError:
            cur_loop = None
        return (
            self.browser is not None
            and not self.stopped
            and self._loop is cur_loop
        )

    async def _ensure_camoufox_installed(self) -> None:
        try:
            import camoufox  # noqa: F401
        except ImportError:
            proc_pip = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "pip",
                "install",
                "-q",
                "camoufox[geoip]==0.5.6",
                "fpgen==1.2.1",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc_pip.wait()

        if os.geteuid() == 0 and shutil.which("apt-get") and not (
            os.path.exists("/usr/lib/x86_64-linux-gnu/libepoxy.so.0")
            or os.path.exists("/tmp/libs/usr/lib/x86_64-linux-gnu/libepoxy.so.0")
        ):
            proc_apt = await asyncio.create_subprocess_shell(
                "DEBIAN_FRONTEND=noninteractive apt-get update -qq && "
                "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "
                "xvfb xkb-data x11-xkb-utils libgtk-3-0 libepoxy0 libcloudproviders0 libdbus-glib-1-2 libasound2 >/dev/null 2>&1",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc_apt.wait()

        has_bin = bool(
            glob.glob("/home/user/.cache/camoufox/browsers/official/*/camoufox-bin")
            or glob.glob("/root/.cache/camoufox/browsers/official/*/camoufox-bin")
        )
        if has_bin:
            return
        os.makedirs("/var/tmp/cfx_tmp", exist_ok=True)
        env = os.environ.copy()
        env["TMPDIR"] = "/var/tmp/cfx_tmp"
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "camoufox",
            "fetch",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
        )
        await proc.wait()

    async def ensure(self) -> None:
        cur_loop = asyncio.get_running_loop()
        if self._loop is not cur_loop:
            self.sem = asyncio.Semaphore(int(os.environ.get("G2S_LOCAL_SOLVER_WORKERS", "12")))
            self._key_locks = {}
            self._key_refs = {}
            self._start_lock = asyncio.Lock()
            self.browser = None
            self._camoufox = None
            self.stopped = False
            self._loop = cur_loop

        async with self._start_lock:
            if self._is_alive():
                return
            if self.browser is not None or self._camoufox is not None:
                try:
                    if self._camoufox is not None:
                        await self._camoufox.__aexit__(None, None, None)
                except Exception:
                    pass
                self._camoufox = None
                self.browser = None

            await self._ensure_camoufox_installed()
            _ensure_xvfb_and_env()

            from camoufox import DefaultAddons
            from camoufox.async_api import AsyncCamoufox

            profile = os.environ.get("G2S_TS_PROFILE_DIR", "/var/tmp/g2s_ts_profile")
            os.makedirs(profile, exist_ok=True)
            for lock_name in ("lock", ".parentlock"):
                lp = os.path.join(profile, lock_name)
                if os.path.lexists(lp):
                    try:
                        os.unlink(lp)
                    except Exception:
                        pass

            kwargs = dict(
                headless=False,
                humanize=True,
                persistent_context=True,
                user_data_dir=profile,
                os=["windows", "macos", "linux"],
                locale="en-US",
                exclude_addons=[DefaultAddons.UBO],
            )
            solver_proxy = (os.environ.get("SOLVER_PROXY") or "").strip()
            if solver_proxy:
                kwargs["proxy"] = {"server": solver_proxy}
                kwargs["geoip"] = True

            self._camoufox = AsyncCamoufox(**kwargs)
            self.browser = await self._camoufox.__aenter__()
            self.stopped = False
            self.generation += 1
            gen = self.generation

            def _on_close(_ctx):
                if self.generation == gen:
                    self.stopped = True

            try:
                self.browser.on("close", _on_close)
            except Exception:
                pass
            log.info("Local Camoufox Turnstile solver ready (gen %d)", gen)

    async def shutdown(self, generation: Optional[int] = None) -> None:
        if generation is not None and generation != self.generation:
            return
        if self.stopped and self.browser is None:
            return
        self.stopped = True
        if self._camoufox is not None:
            try:
                await self._camoufox.__aexit__(None, None, None)
            except Exception:
                pass
        self._camoufox = None
        self.browser = None

    async def solve(
        self,
        sitekey: str,
        siteurl: str,
        timeout: int = 35,
        action: Optional[str] = None,
        cdata: Optional[str] = None,
    ) -> str:
        clean_action = sanitize_turnstile_action(action)
        async with self.sem:
            for attempt in (1, 2):
                page = None
                await self.ensure()
                gen = self.generation
                try:
                    page = await self.browser.new_page()
                    t0 = time.monotonic()
                    target = siteurl if siteurl.endswith("/") else siteurl + "/"
                    widget_div = (
                        f'<div class="cf-turnstile" style="background:white;" data-sitekey="{_attr(sitekey)}"'
                        + (f' data-action="{_attr(clean_action)}"' if clean_action else "")
                        + (f' data-cdata="{_attr(cdata)}"' if cdata else "")
                        + "></div>"
                    )
                    body = _HOST_HTML.replace("__WIDGET__", widget_div)
                    await page.route(
                        target,
                        lambda route: route.fulfill(
                            body=body,
                            status=200,
                            content_type="text/html; charset=utf-8",
                        ),
                    )
                    await page.goto(target, wait_until="domcontentloaded", timeout=20_000)
                    try:
                        await page.eval_on_selector(
                            "//div[@class='cf-turnstile']",
                            "el => el.style.width = '70px'",
                        )
                    except Exception:
                        pass

                    deadline = t0 + max(15, timeout)
                    while time.monotonic() < deadline:
                        try:
                            val = await page.input_value(
                                "[name=cf-turnstile-response]", timeout=400
                            )
                        except Exception:
                            val = None
                        if val:
                            self.solve_count += 1
                            return val
                        try:
                            await page.locator("//div[@class='cf-turnstile']").click(
                                timeout=400
                            )
                        except Exception:
                            pass
                        await asyncio.sleep(0.3)
                    raise SolverError(f"local_camoufox_timeout after {timeout}s")
                except Exception as exc:
                    msg = str(exc).lower()
                    if attempt == 1 and any(h in msg for h in _DEAD_BROWSER_HINTS):
                        await self.shutdown(gen)
                        continue
                    if isinstance(exc, SolverError):
                        raise
                    raise SolverError(f"local_camoufox_error: {exc}") from exc
                finally:
                    if page is not None:
                        try:
                            await page.unroute_all()
                        except Exception:
                            pass
                        try:
                            await page.close()
                        except Exception:
                            pass
        raise SolverError("local_camoufox_failed")


_LOCAL_SOLVER = _LocalCamoufoxSolver(
    max_concurrent=max(20, int(os.environ.get("G2S_LOCAL_SOLVER_WORKERS", "20") or "20"))
)


class TurnstileSolver:
    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: int = 45,
        min_interval: float = 0.6,
    ):
        self.base = (base_url or "").rstrip("/")
        self.api_key = (
            api_key
            or os.environ.get("G2S_SOLVER_API_KEY")
            or os.environ.get("SOLVER_API_KEY")
            or None
        )
        self.timeout = timeout
        self.min_interval = min_interval
        self._lock = asyncio.Lock()
        self._last = 0.0
        self._session: aiohttp.ClientSession | None = None
        self._session_loop = None
        self._remote_unauth_until: float = 0.0

    def _headers(self):
        fake_ip = f"49.36.{random.randint(10, 245)}.{random.randint(10, 245)}"
        h = {
            "Content-Type": "application/json",
            "X-Forwarded-For": fake_ip,
            "X-Real-IP": fake_ip,
        }
        if self.api_key:
            h["X-API-Key"] = self.api_key
        return h

    async def _get_session(self) -> aiohttp.ClientSession:
        loop = asyncio.get_running_loop()
        if (
            self._session is None
            or self._session.closed
            or self._session_loop is not loop
        ):
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=32, ttl_dns_cache=300),
            )
            self._session_loop = loop
        return self._session

    async def health(self) -> dict:
        remote_info = {}
        if self.base:
            try:
                s = await self._get_session()
                async with s.get(
                    self.base + "/health",
                    headers=self._headers(),
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    remote_info = await r.json(content_type=None)
            except Exception as e:
                remote_info = {"remote_error": str(e)}
        return {
            "status": "ok",
            "mode": "hybrid_camoufox",
            "local_solves": _LOCAL_SOLVER.solve_count,
            "remote": remote_info,
        }

    async def solve_turnstile(
        self,
        sitekey: str,
        siteurl: str,
        action: str | None = None,
        cdata: str | None = None,
    ) -> str:
        global _GLOBAL_LAST_SOLVE, _GLOBAL_REMOTE_UNAUTH_UNTIL
        clean_action = sanitize_turnstile_action(action)
        body = {"sitekey": sitekey, "siteurl": siteurl, "timeout": self.timeout}
        if clean_action:
            body["action"] = clean_action
        if cdata:
            body["cdata"] = cdata

        last_err = None
        now_m = time.monotonic()
        use_remote = (
            bool(self.base)
            and now_m >= self._remote_unauth_until
            and now_m >= _GLOBAL_REMOTE_UNAUTH_UNTIL
            and not (not self.api_key and "cf.vltcx.eu.cc" in self.base)
        )
        # 1. Try remote solver if configured and not known-unauthorized/unresponsive
        if use_remote:
            for attempt in range(2):
                async with _GLOBAL_SOLVER_SEM:
                    async with _GLOBAL_START_LOCK:
                        wait = self.min_interval - (time.monotonic() - _GLOBAL_LAST_SOLVE)
                        if wait > 0:
                            await asyncio.sleep(wait)
                        _GLOBAL_LAST_SOLVE = time.monotonic()
                    try:
                        s = await self._get_session()
                        async with s.post(
                            self.base + "/solve",
                            json=body,
                            headers=self._headers(),
                            timeout=aiohttp.ClientTimeout(total=12),
                        ) as r:
                            status_code = r.status
                            data = await r.json(content_type=None)
                    except Exception as e:
                        last_err = SolverError(f"network_error: {e}")
                        self._remote_unauth_until = time.monotonic() + 600.0
                        _GLOBAL_REMOTE_UNAUTH_UNTIL = time.monotonic() + 600.0
                        break

                    if isinstance(data, dict) and data.get("token"):
                        return data["token"]

                    err_code = (
                        data.get("error_code")
                        if isinstance(data, dict)
                        else f"http_{status_code}"
                    )
                    err_msg = data.get("error") if isinstance(data, dict) else str(data)
                    last_err = SolverError(f"{err_code}: {err_msg}")
                    if status_code in (401, 403, 500, 502, 503, 504) or err_code in (
                        "unauthorized",
                        "forbidden",
                        "invalid_api_key",
                    ):
                        self._remote_unauth_until = time.monotonic() + 1800.0
                        _GLOBAL_REMOTE_UNAUTH_UNTIL = time.monotonic() + 1800.0
                        log.info(
                            "Remote Turnstile solver returned %s (%s); switching to built-in Camoufox solver",
                            status_code,
                            err_code,
                        )
                        break
                    if err_code in ("too_many_concurrent", "rate_limited"):
                        await asyncio.sleep(1.0)
                        continue
                    break

        # 2. Built-in Camoufox local solver fallback (fast, zero external rate limits)
        try:
            return await _LOCAL_SOLVER.solve(
                sitekey=sitekey,
                siteurl=siteurl,
                timeout=min(max(self.timeout, 25), 40),
                action=clean_action,
                cdata=cdata,
            )
        except Exception as local_exc:
            raise SolverError(
                f"Turnstile solve failed (remote={last_err}, local={local_exc})"
            ) from local_exc
