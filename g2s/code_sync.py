"""
MongoDB + GitHub Code Persistence, Hot-Reload & Anti-Rollback Boot Guard for TheDrunkBots.

Guarantees:
  1. Any code fix or dynamic rule applied by the Autonomous AI Engineer is persisted in
     MongoDB (`g2sv2.code_files` and `g2sv2.code_revisions`) AND pushed to GitHub (when
     `github_token` is configured).
  2. Boot-Time Anti-Rollback Security (`hydrate_from_mongo_on_boot`):
     If the VPS / Railway container restarts from a hardcoded Docker image or older GitHub
     commit, the server automatically restores the latest verified `ai_modified` code files
     from MongoDB onto disk and hot-reloads the Python modules in memory BEFORE serving
     requests — ensuring old hardcoded code never overwrites live AI fixes.
  3. Every code edit is syntax-checked (`compile()`), diffed (`difflib`), archived in
     `code_revisions` with 1-click rollback support, and hot-applied to the running engine.
"""
import asyncio
import base64
import difflib
import hashlib
import importlib
import os
import sys
import time
import uuid
from typing import Any

import aiohttp


TRACKED_FILES = [
    "g2s/engine.py",
    "g2s/scripts.py",
    "g2s/bot.py",
    "g2s/db.py",
    "g2s/payment.py",
    "g2s/solver.py",
    "g2s/ws_tunnel.py",
    "g2s/ai_engineer.py",
    "g2s/code_sync.py",
    "server.py",
    "web/index.html",
    "requirements.txt",
    "Dockerfile",
    "docker-compose.yml",
]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class CodeSyncManager:
    def __init__(self, root_dir: str, db: Any, bypasser_Getter=None):
        self.root_dir = os.path.abspath(root_dir)
        self.db = db
        self.get_bypasser = bypasser_Getter
        self._lock = asyncio.Lock()
        self.local_revisions: list[dict] = []
        self.hydrated_files: list[str] = []
        self._known_local_hashes: dict[str, str] = {}
        self._boot_ts: float = time.time()
        self._last_restart_ack_ts: float = time.time()
        self.last_sync_status: dict[str, Any] = {
            "boot_hydrated": [],
            "last_commit_at": None,
            "last_github_sync": None,
            "tracked_count": len(TRACKED_FILES),
        }

    def _abs_path(self, rel_path: str) -> str:
        clean = rel_path.lstrip("/").replace("\\", "/")
        full = os.path.abspath(os.path.join(self.root_dir, clean))
        if not full.startswith(self.root_dir):
            raise ValueError(f"Path outside repository root: {rel_path}")
        return full

    def read_local_file(self, rel_path: str) -> str:
        full = self._abs_path(rel_path)
        with open(full, "r", encoding="utf-8") as f:
            return f.read()

    def validate_syntax(self, rel_path: str, content: str) -> tuple[bool, str | None]:
        if rel_path.endswith(".py"):
            try:
                compile(content, rel_path, "exec")
            except SyntaxError as e:
                return False, f"SyntaxError in {rel_path} at line {e.lineno}: {e.msg}"
            except Exception as e:
                return False, f"Compile error in {rel_path}: {e}"
        return True, None

    async def hydrate_from_mongo_on_boot(self) -> list[str]:
        """Anti-Rollback Boot Guard:
        On VPS/Railway startup, checks MongoDB `g2sv2.code_files`. If MongoDB holds a
        verified AI-modified revision (`ai_modified=True`) that differs from the local
        container disk file, restores it onto disk and hot-reloads the module in memory.
        Also seeds any untracked files into MongoDB so the cloud snapshot is complete.
        """
        restored: list[str] = []
        # Apply dynamic_rules to engine immediately
        try:
            from . import engine as _eng
            _eng.set_dynamic_rules(self.db.settings.get("dynamic_rules") or {})
        except Exception:
            pass

        if not self.db.connected or self.db.db is None:
            return restored

        try:
            meta_list = await self.db.db.code_files.find(
                {},
                {"path": 1, "sha256": 1, "revision": 1, "ai_modified": 1, "updated_at": 1},
            ).to_list(length=50)
            meta_by_path = {
                (m.get("path") or m.get("_id")): m
                for m in meta_list
                if isinstance(m, dict) and (m.get("path") or m.get("_id"))
            }

            for rel_path in TRACKED_FILES:
                full = self._abs_path(rel_path)
                if not os.path.exists(full):
                    continue
                local_content = self.read_local_file(rel_path)
                local_hash = _sha256(local_content)
                meta = meta_by_path.get(rel_path)

                if meta is not None:
                    mongo_hash = meta.get("sha256")
                    mongo_updated_at = float(meta.get("updated_at") or 0)
                    cur_rev = int(meta.get("revision") or 1)
                    if mongo_hash and mongo_hash != local_hash:
                        doc = (
                            await self.db.db.code_files.find_one({"_id": rel_path})
                            or await self.db.db.code_files.find_one({"path": rel_path})
                        )
                        mongo_content = str((doc or {}).get("content") or "")

                        # Feature markers: if the Docker/deploy image has product features
                        # that MongoDB snapshot is missing, prefer deploy and push UP to Mongo
                        # (prevents Anti-Rollback from wiping Loop Mode / new panels on every restart)
                        _FEATURE_MARKERS = {
                            "g2s/bot.py": (
                                "loop:setup",
                                "_cmd_loop_setup",
                                "/loop_setup",
                                "Loop Setup",
                                "loop:conc:",
                                "_finish_loop_setup",
                                "concurrency",
                            ),
                            "g2s/engine.py": (
                                "browser_handoff_url",
                                "_try_shortners_workers_direct",
                                "_fresh_request_identity",
                                "VPLink turnstile bind",
                                "Fresh proxy for this",
                            ),
                            "g2s/code_sync.py": (
                                "prefer_deploy",
                                "G2S_PREFER_DEPLOY",
                                "deploy_prefer",
                                "FEATURE_MARKERS",
                            ),
                            "server.py": (
                                "Rotated",
                                "_rotate_hosts",
                                "v2links.",
                            ),
                        }
                        markers = _FEATURE_MARKERS.get(rel_path) or ()
                        local_has_features = bool(markers) and any(m in local_content for m in markers)
                        mongo_has_features = bool(markers) and any(m in mongo_content for m in markers)
                        prefer_deploy = bool(local_has_features and not mongo_has_features)

                        # Env override: G2S_PREFER_DEPLOY=1 always keeps container files
                        if str(os.environ.get("G2S_PREFER_DEPLOY", "")).strip().lower() in (
                            "1", "true", "yes", "on",
                        ):
                            prefer_deploy = True

                        if prefer_deploy:
                            # Push local deploy version INTO Mongo so next boots keep it
                            try:
                                await self.db.db.code_files.update_one(
                                    {"_id": rel_path},
                                    {"$set": {
                                        "path": rel_path,
                                        "content": local_content,
                                        "sha256": local_hash,
                                        "revision": cur_rev + 1,
                                        "ai_modified": True,
                                        "updated_at": time.time(),
                                        "author": "deploy_prefer",
                                        "last_commit_msg": "Deploy image preferred over stale Mongo snapshot (feature markers)",
                                    }},
                                    upsert=True,
                                )
                                print(
                                    f"⬆ Boot: kept deploy {rel_path} (has newer features) and synced to MongoDB",
                                    flush=True,
                                )
                                self.db.add_system_log(
                                    f"Boot Prefer-Deploy: kept container {rel_path} and pushed to MongoDB",
                                    level="INFO",
                                    component="code_sync",
                                )
                            except Exception as e:
                                print(f"Boot prefer-deploy push failed for {rel_path}: {e}", flush=True)
                        elif (
                            meta.get("ai_modified")
                            or cur_rev > 1
                            or mongo_updated_at > 1792400000
                        ) and mongo_content:
                            ok, err = self.validate_syntax(rel_path, mongo_content)
                            if ok:
                                with open(full, "w", encoding="utf-8") as f:
                                    f.write(mongo_content)
                                if mongo_updated_at > 0:
                                    try:
                                        os.utime(full, (mongo_updated_at, mongo_updated_at))
                                    except Exception:
                                        pass
                                restored.append(rel_path)
                                self.db.add_system_log(
                                    f"Boot Anti-Rollback Guard: Restored AI-updated {rel_path} "
                                    f"(rev #{cur_rev}) from MongoDB",
                                    level="INFO",
                                    component="code_sync",
                                )
                else:
                    # Seed initial baseline in MongoDB only when no document exists yet
                    await self.db.db.code_files.update_one(
                        {"_id": rel_path},
                        {"$set": {
                            "path": rel_path,
                            "content": local_content,
                            "sha256": local_hash,
                            "baseline_sha256": local_hash,
                            "revision": 1,
                            "ai_modified": False,
                            "updated_at": time.time(),
                            "author": "baseline",
                            "last_commit_msg": "Initial baseline sync",
                        }},
                        upsert=True,
                    )

            # Load recent revisions metadata into memory mirror (exclude large file contents)
            cursor = self.db.db.code_revisions.find(
                {},
                {"content": 0, "old_content": 0, "new_content": 0},
            ).sort("at", -1).limit(25)
            revs = []
            async for rdoc in cursor:
                rdoc.pop("_id", None)
                revs.append(rdoc)
            self.local_revisions = revs
        except Exception as e:
            print("CodeSync boot hydration warning:", e, flush=True)

        if restored:
            self.hydrated_files = restored
            self.last_sync_status["boot_hydrated"] = restored
            await self.hot_reload_modules(restored)

        for rel_path in TRACKED_FILES:
            full = self._abs_path(rel_path)
            if os.path.exists(full):
                try:
                    self._known_local_hashes[rel_path] = _sha256(self.read_local_file(rel_path))
                except Exception:
                    pass

        self.start_remote_sync_loop(interval=8.0)
        return restored

    async def trigger_graceful_restart(self, reason: str = "Admin requested restart"):
        """Closes active browser workers cleanly and replaces the current Python process in-place via os.execv."""
        self.db.add_system_log(
            f"System Restart Triggered: {reason}",
            level="INFO",
            component="code_sync",
        )
        bp = self.get_bypasser() if callable(self.get_bypasser) else None
        if bp is not None:
            try:
                await asyncio.wait_for(bp.close(), timeout=5.0)
            except Exception:
                pass
        try:
            solver_mod = sys.modules.get("g2s.solver")
            local_solver = getattr(solver_mod, "_LOCAL_SOLVER", None) if solver_mod else None
            if local_solver is not None:
                for p in list(getattr(local_solver, "_pages", []) or []):
                    try:
                        await p.close()
                    except Exception:
                        pass
                cm = getattr(local_solver, "_cm", None)
                if cm is not None:
                    try:
                        await asyncio.wait_for(cm.__aexit__(None, None, None), timeout=3.0)
                    except Exception:
                        pass
                xvfb_p = getattr(local_solver, "_xvfb_proc", None)
                if xvfb_p is not None:
                    try:
                        xvfb_p.terminate()
                    except Exception:
                        pass
        except Exception:
            pass
        await asyncio.sleep(0.3)
        os.execv(sys.executable, [sys.executable] + sys.argv)

    def start_remote_sync_loop(self, interval: float = 8.0):
        """Starts a background loop that polls MongoDB `code_files` & `settings` for newer revisions
        and hot-reloads changed modules in memory without requiring a manual container redeploy.
        """
        task = getattr(self, "_remote_sync_task", None)
        if task and not task.done():
            return
        try:
            loop = asyncio.get_running_loop()
            self._remote_sync_task = loop.create_task(self._remote_sync_loop(interval))
        except Exception:
            pass

    async def _remote_sync_loop(self, interval: float = 8.0):
        while True:
            try:
                await asyncio.sleep(interval)
                if not self.db.connected or self.db.db is None:
                    continue
                # 1. Check remote restart trigger or dynamic_rules changes in g2sv2.settings
                try:
                    s_doc = await self.db.db.settings.find_one(
                        {"_id": {"$in": ["global", "main"]}},
                        {"remote_restart_ts": 1, "remote_restart_reason": 1, "dynamic_rules": 1},
                    )
                    if isinstance(s_doc, dict):
                        dyn_r = s_doc.get("dynamic_rules")
                        if isinstance(dyn_r, dict):
                            from . import engine as _eng
                            _eng.set_dynamic_rules(dyn_r)
                        req_restart_ts = float(s_doc.get("remote_restart_ts") or 0)
                        if req_restart_ts > self._last_restart_ack_ts:
                            self._last_restart_ack_ts = max(time.time(), req_restart_ts)
                            await self.db.db.settings.update_one(
                                {"_id": s_doc.get("_id", "global")},
                                {"$set": {"remote_restart_ack_ts": self._last_restart_ack_ts}},
                            )
                            await self.hydrate_from_mongo_on_boot()
                            await self.trigger_graceful_restart(
                                reason=str(s_doc.get("remote_restart_reason") or "Remote MongoDB restart trigger")
                            )
                            return
                except Exception:
                    pass

                # 2. Fetch all tracked file metadata in a single fast query
                meta_list = await self.db.db.code_files.find(
                    {},
                    {"path": 1, "sha256": 1, "revision": 1, "ai_modified": 1, "updated_at": 1},
                ).to_list(length=50)
                meta_by_path = {
                    (m.get("path") or m.get("_id")): m
                    for m in meta_list
                    if isinstance(m, dict) and (m.get("path") or m.get("_id"))
                }

                changed: list[str] = []
                pulled_from_mongo: list[str] = []
                for rel_path in TRACKED_FILES:
                    full = self._abs_path(rel_path)
                    if not os.path.exists(full):
                        continue
                    local_content = self.read_local_file(rel_path)
                    local_hash = _sha256(local_content)
                    local_mtime = os.path.getmtime(full)
                    known_local_hash = self._known_local_hashes.get(rel_path)
                    meta = meta_by_path.get(rel_path)
                    if not meta:
                        continue
                    remote_hash = meta.get("sha256")
                    remote_updated_at = float(meta.get("updated_at") or 0)
                    cur_rev = int(meta.get("revision") or 1)
                    if remote_hash and remote_hash != local_hash:
                        # If local file was NOT modified since boot/last sync, MongoDB was updated remotely -> pull!
                        local_was_edited_in_place = (
                            known_local_hash is not None
                            and local_hash != known_local_hash
                            and local_mtime > remote_updated_at + 5.0
                        )
                        if local_was_edited_in_place:
                            new_rev = cur_rev + 1
                            now_ts = max(time.time(), local_mtime)
                            await self.db.db.code_files.update_one(
                                {"_id": rel_path},
                                {"$set": {
                                    "path": rel_path,
                                    "content": local_content,
                                    "sha256": local_hash,
                                    "revision": new_rev,
                                    "ai_modified": True,
                                    "updated_at": now_ts,
                                    "author": "local-live-sync",
                                    "last_commit_msg": f"Auto-synced local change on {rel_path} (rev #{new_rev})",
                                }},
                                upsert=True,
                            )
                            self._known_local_hashes[rel_path] = local_hash
                            changed.append(rel_path)
                        elif (
                            meta.get("ai_modified")
                            or cur_rev > 1
                            or remote_updated_at > 1792400000
                        ):
                            doc = (
                                await self.db.db.code_files.find_one({"_id": rel_path})
                                or await self.db.db.code_files.find_one({"path": rel_path})
                            )
                            if doc and doc.get("content"):
                                mongo_content = str(doc["content"])
                                ok, _ = self.validate_syntax(rel_path, mongo_content)
                                if ok:
                                    tmp_p = full + ".tmp"
                                    with open(tmp_p, "w", encoding="utf-8") as f:
                                        f.write(mongo_content)
                                    os.replace(tmp_p, full)
                                    if remote_updated_at > 0:
                                        try:
                                            os.utime(full, (remote_updated_at, remote_updated_at))
                                        except Exception:
                                            pass
                                    self._known_local_hashes[rel_path] = _sha256(mongo_content)
                                    changed.append(rel_path)
                                    pulled_from_mongo.append(rel_path)
                if changed:
                    await self.hot_reload_modules(changed)
                    self.db.add_system_log(
                        f"Live Cloud Sync: Hot-reloaded {len(changed)} updated file(s) from MongoDB ({', '.join(changed)})",
                        level="INFO",
                        component="code_sync",
                    )
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(interval)

    async def hot_reload_modules(self, rel_paths: list[str]) -> list[str]:
        """Hot-reloads modified Python modules in memory and refreshes live runtime instances."""
        reloaded = []
        try:
            from . import engine as _eng
            _eng.set_dynamic_rules(self.db.settings.get("dynamic_rules") or {})
        except Exception:
            pass

        module_order = [
            ("g2s/scripts.py", "g2s.scripts", None, None),
            ("g2s/solver.py", "g2s.solver", None, None),
            ("g2s/db.py", "g2s.db", "db", "Database"),
            ("g2s/ws_tunnel.py", "g2s.ws_tunnel", "ws_tunnels", "WsTunnelManager"),
            ("g2s/payment.py", "g2s.payment", None, None),
            ("g2s/engine.py", "g2s.engine", "bypasser", "Bypasser"),
            ("g2s/bot.py", "g2s.bot", "bot", "TelegramBot"),
            ("g2s/code_sync.py", "g2s.code_sync", "code_sync", "CodeSyncManager"),
            ("g2s/ai_engineer.py", "g2s.ai_engineer", "ai_engineer", "AIEngineer"),
        ]
        norm_set = {p.lstrip("/").replace("\\", "/") for p in rel_paths}
        if "g2s/scripts.py" in norm_set or "g2s/solver.py" in norm_set:
            norm_set.add("g2s/engine.py")

        main_mod = sys.modules.get("__main__")
        for rel_p, mod_name, attr_name, cls_name in module_order:
            if rel_p in norm_set and mod_name in sys.modules:
                try:
                    mod = importlib.reload(sys.modules[mod_name])
                    reloaded.append(mod_name)
                    if mod_name == "g2s.engine":
                        mod.set_dynamic_rules(self.db.settings.get("dynamic_rules") or {})
                        bp = self.get_bypasser() if callable(self.get_bypasser) else None
                        if bp is not None:
                            new_cls = mod.Bypasser
                            bp.__class__ = new_cls
                            if isinstance(getattr(bp, "_inflight_urls", None), dict):
                                bp._inflight_urls.clear()
                            solver_mod = sys.modules.get("g2s.solver")
                            if solver_mod and hasattr(solver_mod, "TurnstileSolver") and getattr(bp, "cfg", None):
                                try:
                                    bp.solver = solver_mod.TurnstileSolver(bp.cfg.solver_url, bp.cfg.solver_api_key)
                                except Exception:
                                    pass
                            for w in getattr(bp, "_workers", []) or []:
                                w.__class__ = new_cls
                                if getattr(bp, "solver", None) is not None:
                                    w.solver = bp.solver
                        if main_mod is not None and isinstance(getattr(main_mod, "_inflight", None), dict):
                            main_mod._inflight.clear()
                    if mod_name == "g2s.db" and hasattr(mod, "Database"):
                        self.db.__class__ = mod.Database
                    if mod_name == "g2s.ws_tunnel" and hasattr(mod, "WsDeviceSession"):
                        if main_mod is not None:
                            wst = getattr(main_mod, "ws_tunnels", None)
                            if wst is not None:
                                for sess in list((getattr(wst, "sessions", None) or {}).values()):
                                    sess.__class__ = mod.WsDeviceSession
                                    if hasattr(sess, "rebind_local_proxy"):
                                        try:
                                            await sess.rebind_local_proxy()
                                        except Exception:
                                            pass
                    if main_mod is not None and attr_name and cls_name:
                        inst = getattr(main_mod, attr_name, None)
                        new_cls = getattr(mod, cls_name, None)
                        if inst is not None and new_cls is not None:
                            inst.__class__ = new_cls
                        if new_cls is not None and hasattr(main_mod, cls_name):
                            setattr(main_mod, cls_name, new_cls)
                except Exception as e:
                    self.db.add_system_log(f"Hot-reload warning for {mod_name}: {e}", level="WARN", component="code_sync")
        return reloaded

    async def commit_file(
        self,
        rel_path: str,
        new_content: str,
        reason: str,
        author: str = "AI-Engineer",
        verified_urls: list[str] | None = None,
        push_github: bool = True,
    ) -> dict[str, Any]:
        """Validates syntax, writes file to disk, hot-reloads in memory, saves to MongoDB
        `code_files` + `code_revisions`, and pushes to GitHub if configured.
        """
        async with self._lock:
            clean_path = rel_path.lstrip("/").replace("\\", "/")
            ok, err = self.validate_syntax(clean_path, new_content)
            if not ok:
                raise ValueError(err or "Syntax validation failed")

            full = self._abs_path(clean_path)
            old_content = ""
            if os.path.exists(full):
                old_content = self.read_local_file(clean_path)

            old_hash = _sha256(old_content)
            new_hash = _sha256(new_content)

            diff_lines = list(
                difflib.unified_diff(
                    old_content.splitlines(),
                    new_content.splitlines(),
                    fromfile=f"a/{clean_path}",
                    tofile=f"b/{clean_path}",
                    lineterm="",
                )
            )
            diff_text = "\n".join(diff_lines[:300])

            # Write atomically to disk
            tmp_path = full + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(new_content)
            os.replace(tmp_path, full)
            self._known_local_hashes[clean_path] = new_hash

            now = time.time()
            rev_id = uuid.uuid4().hex[:10]
            rev_num = 1
            if self.db.connected and self.db.db is not None:
                try:
                    existing = await self.db.db.code_files.find_one({"_id": clean_path})
                    rev_num = int((existing or {}).get("revision") or 1) + 1
                except Exception:
                    rev_num = 2

            rev_entry = {
                "id": rev_id,
                "path": clean_path,
                "revision": rev_num,
                "old_sha256": old_hash,
                "new_sha256": new_hash,
                "diff": diff_text,
                "old_content": old_content,
                "new_content": new_content,
                "reason": reason,
                "author": author,
                "verified_urls": list(verified_urls or []),
                "at": now,
                "github_pushed": False,
                "github_sha": None,
            }

            if push_github:
                gh_res = await self.push_file_to_github(
                    clean_path,
                    new_content,
                    f"🤖 [{author}] {reason}",
                )
                if gh_res.get("ok"):
                    rev_entry["github_pushed"] = True
                    rev_entry["github_sha"] = gh_res.get("commit_sha")

            self.local_revisions.insert(0, {k: v for k, v in rev_entry.items() if k not in ("old_content", "new_content")})
            self.local_revisions = self.local_revisions[:40]

            if self.db.connected and self.db.db is not None:
                try:
                    await self.db.db.code_files.update_one(
                        {"_id": clean_path},
                        {"$set": {
                            "path": clean_path,
                            "content": new_content,
                            "sha256": new_hash,
                            "revision": rev_num,
                            "ai_modified": True,
                            "updated_at": now,
                            "author": author,
                            "last_commit_msg": reason,
                            "verified_urls": list(verified_urls or []),
                            "github_pushed": rev_entry["github_pushed"],
                            "github_sha": rev_entry["github_sha"],
                        }},
                        upsert=True,
                    )
                    await self.db.db.code_revisions.insert_one({"_id": rev_id, **rev_entry})
                except Exception as e:
                    print("Mongo code commit warning:", e, flush=True)

            reloaded = await self.hot_reload_modules([clean_path])
            self.last_sync_status["last_commit_at"] = now
            self.db.add_system_log(
                f"Committed & hot-reloaded {clean_path} (rev #{rev_num}) by {author}: {reason}",
                level="INFO",
                component="code_sync",
            )
            return {
                "ok": True,
                "revision_id": rev_id,
                "path": clean_path,
                "revision": rev_num,
                "sha256": new_hash,
                "reloaded_modules": reloaded,
                "github_pushed": rev_entry["github_pushed"],
                "github_sha": rev_entry["github_sha"],
                "diff": diff_text,
            }

    async def rollback_revision(self, rev_id: str) -> dict[str, Any]:
        """Rolls back a specific code revision using the archived `old_content` in MongoDB."""
        if not self.db.connected or self.db.db is None:
            return {"ok": False, "error": "MongoDB not connected"}
        doc = await self.db.db.code_revisions.find_one({"_id": rev_id})
        if not doc or not doc.get("old_content") or not doc.get("path"):
            return {"ok": False, "error": f"Revision {rev_id} not found"}
        res = await self.commit_file(
            doc["path"],
            doc["old_content"],
            reason=f"Rollback of revision {rev_id} ({doc.get('reason', '')})",
            author="Admin-Rollback",
        )
        return res

    async def push_file_to_github(self, rel_path: str, content: str, commit_message: str) -> dict[str, Any]:
        """Pushes a single file directly to GitHub via the GitHub Contents REST API."""
        token = (self.db.settings.get("github_token") or os.environ.get("GITHUB_TOKEN") or "").strip()
        repo = (self.db.settings.get("github_repo") or "Urvashi212144/gss-free").strip()
        branch = (self.db.settings.get("github_branch") or "main").strip()
        if not token or not repo:
            return {"ok": False, "reason": "github_token not configured (saved to MongoDB cloud persistence)"}

        clean_path = rel_path.lstrip("/").replace("\\", "/")
        api_url = f"https://api.github.com/repos/{repo}/contents/{clean_path}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "TheDrunkBots-AI-Engineer",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20), headers=headers) as s:
                cur_sha = None
                async with s.get(api_url, params={"ref": branch}) as r0:
                    if r0.status == 200:
                        j0 = await r0.json()
                        cur_sha = j0.get("sha")
                payload: dict[str, Any] = {
                    "message": commit_message,
                    "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
                    "branch": branch,
                }
                if cur_sha:
                    payload["sha"] = cur_sha
                async with s.put(api_url, json=payload) as r1:
                    j1 = await r1.json(content_type=None)
                    if r1.status in (200, 201) and isinstance(j1, dict):
                        commit_sha = (j1.get("commit") or {}).get("sha")
                        self.last_sync_status["last_github_sync"] = time.time()
                        return {"ok": True, "commit_sha": commit_sha, "repo": repo, "branch": branch}
                    return {"ok": False, "error": f"HTTP {r1.status}: {j1}"}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    async def sync_all_to_mongo_and_github(self, reason: str = "Manual full codebase sync") -> dict[str, Any]:
        """Saves all tracked files to MongoDB `code_files` and pushes them to GitHub if token is set."""
        synced_mongo = []
        pushed_gh = []
        gh_errors = []
        now = time.time()
        meta_by_path: dict[str, dict] = {}
        if self.db.connected and self.db.db is not None:
            try:
                m_list = await self.db.db.code_files.find(
                    {}, {"path": 1, "sha256": 1, "revision": 1}
                ).to_list(length=50)
                meta_by_path = {
                    (m.get("path") or m.get("_id")): m
                    for m in m_list
                    if isinstance(m, dict) and (m.get("path") or m.get("_id"))
                }
            except Exception:
                pass
        for rel_path in TRACKED_FILES:
            full = self._abs_path(rel_path)
            if not os.path.exists(full):
                continue
            content = self.read_local_file(rel_path)
            sha = _sha256(content)
            if self.db.connected and self.db.db is not None:
                try:
                    existing = meta_by_path.get(rel_path)
                    rev_num = int((existing or {}).get("revision") or 1)
                    if not existing or (existing or {}).get("sha256") != sha:
                        if existing:
                            rev_num += 1
                        await self.db.db.code_files.update_one(
                            {"_id": rel_path},
                            {"$set": {
                                "path": rel_path,
                                "content": content,
                                "sha256": sha,
                                "revision": rev_num,
                                "ai_modified": True,
                                "updated_at": now,
                                "last_commit_msg": reason,
                            }},
                            upsert=True,
                        )
                        self._known_local_hashes[rel_path] = sha
                    synced_mongo.append(rel_path)
                except Exception:
                    pass
            if (self.db.settings.get("github_token") or "").strip():
                gh_res = await self.push_file_to_github(rel_path, content, f"🔄 {reason} ({rel_path})")
                if gh_res.get("ok"):
                    pushed_gh.append(rel_path)
                elif gh_res.get("error"):
                    gh_errors.append(f"{rel_path}: {gh_res['error']}")

        return {
            "ok": True,
            "mongo_synced": synced_mongo,
            "github_pushed": pushed_gh,
            "github_configured": bool((self.db.settings.get("github_token") or "").strip()),
            "github_errors": gh_errors,
        }

    async def get_status(self) -> dict[str, Any]:
        files_info = []
        if self.db.connected and self.db.db is not None:
            try:
                cursor = self.db.db.code_files.find({}, {"content": 0})
                async for doc in cursor:
                    files_info.append({
                        "path": doc.get("path") or doc.get("_id"),
                        "revision": doc.get("revision", 1),
                        "sha256": (doc.get("sha256") or "")[:12],
                        "ai_modified": bool(doc.get("ai_modified")),
                        "updated_at": doc.get("updated_at"),
                        "author": doc.get("author", "baseline"),
                        "last_commit_msg": doc.get("last_commit_msg", ""),
                        "github_pushed": bool(doc.get("github_pushed")),
                    })
            except Exception:
                pass
        return {
            "boot_hydrated": self.hydrated_files,
            "github_repo": self.db.settings.get("github_repo") or "Urvashi212144/gss-free",
            "github_branch": self.db.settings.get("github_branch") or "main",
            "github_configured": bool((self.db.settings.get("github_token") or "").strip()),
            "mongo_connected": self.db.connected,
            "files": files_info,
            "revisions": self.local_revisions[:25],
        }
