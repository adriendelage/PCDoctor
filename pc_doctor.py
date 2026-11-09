#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PC Doctor — diagnostic, réparation et maintenance Windows, adaptatif.

Un seul fichier, Python 3.8+, bibliothèque standard uniquement (Tkinter).
Lancer :  python pc_doctor.py      (idéalement en administrateur)

Principe : chaque étape d'analyse produit des constats, ajoute des points à des
« suspects » (RAM, pilote X, disque, alimentation…), peut déclencher d'autres
analyses automatiquement (ex. un vidage mémoire trouvé → analyse du vidage) et
propose des réparations. Les réparations ne s'exécutent JAMAIS sans confirmation.
"""

import base64
import codecs
import ctypes
import datetime
import glob
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import traceback

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except ImportError:  # pragma: no cover
    tk = None

APP_NAME = "PC Doctor"
APP_VERSION = "1.0"
IS_WIN = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WIN else 0
SYSROOT = os.environ.get("SystemRoot", r"C:\Windows")
SYSDRIVE = os.environ.get("SystemDrive", "C:").rstrip("\\").rstrip(":")

# --------------------------------------------------------------------------- #
#  Connaissances
# --------------------------------------------------------------------------- #

BUGCHECKS = {
    0x0A: ("IRQL_NOT_LESS_OR_EQUAL", "Un pilote a accédé à une adresse mémoire invalide à un niveau de priorité élevé. Pilote fautif ou RAM instable."),
    0x1A: ("MEMORY_MANAGEMENT", "Corruption des structures de gestion mémoire. Très souvent la RAM (XMP/EXPO, barrette défectueuse)."),
    0x1E: ("KMODE_EXCEPTION_NOT_HANDLED", "Exception non gérée dans un pilote noyau."),
    0x24: ("NTFS_FILE_SYSTEM", "Problème dans NTFS : corruption du système de fichiers, disque ou RAM."),
    0x3B: ("SYSTEM_SERVICE_EXCEPTION", "Exception lors d'un appel système. Pilote (souvent graphique) ou RAM."),
    0x4E: ("PFN_LIST_CORRUPT", "Liste des pages mémoire corrompue. Quasi toujours la RAM ou un pilote qui écrase la mémoire."),
    0x50: ("PAGE_FAULT_IN_NONPAGED_AREA", "Lecture d'une zone mémoire invalide. Pilote fautif, RAM instable ou corruption système."),
    0x7A: ("KERNEL_DATA_INPAGE_ERROR", "Impossible de relire des données depuis le disque. Disque, câble/contrôleur ou RAM."),
    0x7E: ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "Exception dans un thread système. Pilote le plus souvent."),
    0x9F: ("DRIVER_POWER_STATE_FAILURE", "Un pilote ne répond pas lors d'un changement d'état d'alimentation (veille…)."),
    0xA: ("IRQL_NOT_LESS_OR_EQUAL", "Pilote fautif ou RAM instable."),
    0xC2: ("BAD_POOL_CALLER", "Un pilote a mal utilisé la mémoire du noyau."),
    0x19: ("BAD_POOL_HEADER", "En-tête de mémoire noyau corrompu : pilote qui écrase la mémoire ou RAM."),
    0xD1: ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "Pilote (souvent réseau, Wi-Fi, USB, audio) accédant à une adresse invalide."),
    0xEF: ("CRITICAL_PROCESS_DIED", "Un processus système critique s'est arrêté. Fichiers système, disque ou RAM."),
    0xF7: ("DRIVER_OVERRAN_STACK_BUFFER", "Débordement de pile dans un pilote."),
    0x101: ("CLOCK_WATCHDOG_TIMEOUT", "Un cœur CPU ne répond plus. Overclock/undervolt CPU (PBO, Curve Optimizer), BIOS, CPU."),
    0x116: ("VIDEO_TDR_FAILURE", "Le GPU ne répond plus. Pilote graphique, overclock GPU, alimentation."),
    0x117: ("VIDEO_TDR_TIMEOUT_DETECTED", "Le GPU ne répond plus (récupéré)."),
    0x119: ("VIDEO_SCHEDULER_INTERNAL_ERROR", "Erreur de l'ordonnanceur graphique. Pilote GPU ou GPU instable."),
    0x124: ("WHEA_UNCORRECTABLE_ERROR", "Erreur matérielle remontée par le CPU : overclock/undervolt, alimentation, CPU, carte mère."),
    0x133: ("DPC_WATCHDOG_VIOLATION", "Un pilote bloque le système trop longtemps (souvent stockage, réseau, audio)."),
    0x139: ("KERNEL_SECURITY_CHECK_FAILURE", "Structure noyau corrompue détectée. Pilote ou RAM."),
    0x154: ("UNEXPECTED_STORE_EXCEPTION", "Erreur du gestionnaire de stockage mémoire. Disque ou RAM."),
    0x1E0: ("—", ""),
}

# Modules noyau Microsoft (la présence seule de ceux-ci = « victime », pas coupable)
MS_MODULES = set("""
nt ntkrnlmp ntoskrnl ntkrla57 hal ntfs refs fltmgr ndis tcpip netio storport stornvme storahci classpnp disk
volmgr volmgrx volsnap ci cng ksecdd ksecpkg wdf01000 wdffiltr win32k win32kbase win32kfull win32kns dxgkrnl
dxgmms2 dxgmms1 acpi pci partmgr fileinfo wof wdfilter cldflt afd afunix http mrxsmb mrxsmb20 rdbss usbxhci
ucx01000 usbhub3 usbport usbhub hidclass hidusb kbdclass mouclass intelppm amdppm processr watchdog tm clfs
msrpc fvevol iorate storqosflt bindflt wcifs luafv filecrypt bfs unionfs npsvctrig gameflt ucpd ataport
csc rdyboost mup srv2 srvnet nsiproxy pdc werkernel vmbus vmswitch hvsocket vid winhvr winhv hvservice
fwpkclnt wfplwfs ndisuio netbt tdx bowser mpsdrv wtd cimfs prjflt applockerfltr spaceport mountmgr
fastfat exfat cdfs udfs npfs msfs vwififlt nwifi vwifibus portcls ks ksthunk hdaudbus hdaudio drmk
usbccgp usbstor wpprecorder sgrmagent mssecflt peauth ahcache condrv beep null tbs cmimcext mmcss
storufs nvmedisk iastora ehstorclass bam dam acpiex msisadrv pcw bootvid cea crashdmp dumpfve dump_stornvme
""".split())

MS_FILTERS = set("""
bindflt ucpd wdfilter storqosflt wcifs gameflt cldflt bfs filecrypt luafv unionfs npsvctrig wof fileinfo
prjflt iorate applockerfltr wtd cimfs fsdepends dfsfilter mssecflt sgrmagent
""".split())

KNOWN_DRIVERS = {
    "rt640x64": "Pilote réseau Realtek Ethernet (1G/2,5G)",
    "rtux64w10": "Adaptateur réseau USB Realtek",
    "amdkmdag": "Pilote graphique AMD",
    "atikmdag": "Pilote graphique AMD",
    "atikmpag": "Pilote graphique AMD",
    "amdfendr": "AMD Crash Defender",
    "amdfendrmgr": "AMD Crash Defender",
    "nvlddmkm": "Pilote graphique NVIDIA",
    "igdkmd64": "Pilote graphique Intel",
    "igdkmdn64": "Pilote graphique Intel",
    "vgk": "Riot Vanguard (anti-triche Valorant/LoL)",
    "easyanticheat": "Easy Anti-Cheat",
    "easyanticheat_eos": "Easy Anti-Cheat",
    "bedaisy": "BattlEye (anti-triche)",
    "faceit": "FACEIT (anti-triche)",
    "asio2": "ASUS AsIO (GPU Tweak / Armoury / AI Suite)",
    "asio3": "ASUS AsIO (GPU Tweak / Armoury / AI Suite)",
    "asusgio2": "ASUS GPU Tweak",
    "asusgio3": "ASUS GPU Tweak",
    "gdrv2": "Gigabyte App Center / RGB Fusion",
    "gdrv3": "Gigabyte App Center / RGB Fusion",
    "ene": "Contrôleur RGB ENE (Aura, RGB Fusion…)",
    "mvvad": "Voicemod (carte son virtuelle)",
    "e1d68x64": "Intel Ethernet",
    "e2f68": "Intel Ethernet I225/I226",
    "netwtw10": "Intel Wi-Fi",
    "netwtw14": "Intel Wi-Fi",
    "netwtw08": "Intel Wi-Fi",
    "ibtusb": "Intel Bluetooth",
    "rtkvhd64": "Realtek Audio",
    "vboxdrv": "VirtualBox",
    "aswsp": "Avast/AVG",
    "aswsnx": "Avast/AVG",
    "aswarpot": "Avast/AVG",
    "klif": "Kaspersky",
    "rzudd": "Razer Synapse",
    "lgcorev2": "Logitech",
    "cpuz": "CPU-Z",
    "winring0x64": "WinRing0 (outils de monitoring/RGB, pilote réputé dangereux)",
    "iqvw64e": "Utilitaire Intel (iqvw64e)",
    "nvvad64v": "NVIDIA Broadcast / audio virtuel",
}

RAM_HINT_CODES = {0x1A, 0x4E, 0x50, 0x0A, 0xA, 0x3B, 0x139, 0x19, 0xC2, 0x24, 0xEF}

# --------------------------------------------------------------------------- #
#  Utilitaires
# --------------------------------------------------------------------------- #


def is_admin():
    if not IS_WIN:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def oem_codec():
    if IS_WIN:
        try:
            name = "cp%d" % ctypes.windll.kernel32.GetOEMCP()
            codecs.lookup(name)
            return name
        except Exception:
            pass
    return "utf-8"


def norm(s):
    """Normalise apostrophes/espaces pour les comparaisons FR/EN."""
    return (s or "").replace("\u2019", "'").replace("\u00a0", " ").replace("\u202f", " ").lower()


def sys32(exe):
    """Chemin d'un exécutable System32, en contournant la redirection WOW64."""
    sysnative = os.path.join(SYSROOT, "Sysnative", exe)
    if os.path.exists(sysnative):
        return sysnative
    return os.path.join(SYSROOT, "System32", exe)


def bugcheck_label(code):
    name, expl = BUGCHECKS.get(code, ("code 0x%X" % code, ""))
    return name, expl


class Cancelled(Exception):
    pass


# --------------------------------------------------------------------------- #
#  Parseurs (testables hors Windows)
# --------------------------------------------------------------------------- #


def parse_bugcheck_message(msg):
    """Événement 1001 WER-SystemErrorReporting → (code, params, dump_path)."""
    m = re.search(r"(0x[0-9a-fA-F]{8})\s*\(([^)]*)\)", msg or "")
    code = int(m.group(1), 16) if m else None
    params = [p.strip() for p in m.group(2).split(",")] if m else []
    d = re.search(r"([A-Za-z]:\\[^\s\"']+?\.dmp)", msg or "", re.I)
    return code, params, (d.group(1) if d else None)


def parse_cdb(text):
    """Sortie de cdb '!analyze -v' → dict."""
    out = {}
    for key in ("BUGCHECK_CODE", "MODULE_NAME", "IMAGE_NAME", "FAILURE_BUCKET_ID", "PROCESS_NAME",
                "SYMBOL_NAME", "IMAGE_VERSION", "DEFAULT_BUCKET_ID"):
        m = re.search(r"^\s*%s:\s*(\S.*?)\s*$" % key, text, re.M)
        if m:
            out[key] = m.group(1)
    m = re.search(r"^\s*([A-Z0-9_]+)\s*\(([0-9a-f]+)\)\s*$", text, re.M)
    if m:
        out.setdefault("BUGCHECK_NAME", m.group(1))
        out.setdefault("BUGCHECK_CODE", m.group(2))
    # Pile d'appels
    stack = []
    sm = re.search(r"STACK_TEXT:\s*\n(.*?)(?:\n\s*\n|\n[A-Z_]{6,}:)", text, re.S)
    block = sm.group(1) if sm else ""
    if not block:
        # sortie de 'kn' : lignes '0d fffff886`... module!func'
        block = "\n".join(l for l in text.splitlines() if re.match(r"^\s*[0-9a-f]{2}\s+[0-9a-f`]{8,}", l))
    for mm in re.finditer(r"(?<![!\w])([A-Za-z_][A-Za-z0-9_]*)(?:!|\+0x[0-9a-fA-F]+)", block):
        mod = mm.group(1)
        if mod.lower() in ("kb", "kn", "args", "call", "site"):
            continue
        if not stack or stack[-1] != mod:
            stack.append(mod)
    out["STACK"] = stack
    return out


def third_party_modules(names):
    res = []
    for n in names:
        base = re.sub(r"\.(sys|exe|dll)$", "", (n or "").strip(), flags=re.I).lower()
        if not base or base in MS_MODULES or base.startswith("dump_") or base.startswith("unknown"):
            continue
        if base not in res:
            res.append(base)
    return res


def parse_sfc(text):
    """→ 'ok' | 'found' (verifyonly) | 'repaired' | 'unrepaired' | 'noadmin' | 'failed' | 'unknown'"""
    t = norm(text)
    if "administrateur" in t and "devez" in t or "must be an administrator" in t:
        return "noadmin"
    if "n'a pas pu réparer" in t or "unable to fix" in t or "n'a pas pu reparer" in t:
        return "unrepaired"
    if "réparés" in t or "successfully repaired" in t:
        return "repaired"
    if "aucune violation" in t or "did not find any integrity violations" in t:
        return "ok"
    if "violations d'intégrité" in t or "found integrity violations" in t or "fichiers corrompus" in t:
        return "found"
    if "n'a pas pu effectuer" in t or "could not perform" in t:
        return "failed"
    return "unknown"


def parse_dism(text):
    t = norm(text)
    if "0x800f081f" in t or "fichiers sources sont introuvables" in t or "source files could not be found" in t:
        return "nosource"
    if "aucune altération" in t or "no component store corruption" in t:
        return "clean"
    if "réparable" in t and "magasin" in t or "component store is repairable" in t:
        return "repairable"
    if "restauration a été effectuée" in t or "restore operation completed successfully" in t:
        return "restored"
    if "l'opération a réussi" in t or "operation completed successfully" in t:
        return "success"
    if "erreur" in t or "error" in t:
        return "error"
    return "unknown"


def parse_cbs(text):
    """Journal CBS → (fichiers non réparables, fichiers réparés, magasin corrompu?)"""
    cannot = []
    for m in re.finditer(r"Cannot repair member file \[l:\d+\]'([^']+)'", text):
        if m.group(1) not in cannot:
            cannot.append(m.group(1))
    for m in re.finditer(r"Could not reproject corrupted file \\\?\?\\(.+?);", text):
        f = re.split(r"[\\/]+", m.group(1))[-1]
        if f not in cannot:
            cannot.append(f)
    repaired = []
    for m in re.finditer(r"Repaired file \\SystemRoot\\(.+?) by", text):
        f = re.split(r"[\\/]+", m.group(1))[-1]
        if f not in repaired:
            repaired.append(f)
    store = "source file in store is also corrupted" in text or "in the store, hash mismatch" in text
    return cannot, repaired, store


def last_sfc_session(text, hours=3):
    """Ne garde que les lignes [SR] des dernières heures d'activité SFC."""
    sr = []
    for line in text.splitlines():
        if "[SR]" not in line:
            continue
        m = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
        if m:
            sr.append((m.group(1), line))
    if not sr:
        return ""
    last = datetime.datetime.strptime(sr[-1][0], "%Y-%m-%d %H:%M:%S")
    lim = (last - datetime.timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    return "\n".join(l for ts, l in sr if ts >= lim)


def parse_fltmc(text):
    names = []
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9_\-\.]+)\s+\d+\s+[\d\.]+\s+\d+\s*$", line)
        if m:
            names.append(m.group(1))
    return names


# --------------------------------------------------------------------------- #
#  Exécution de commandes
# --------------------------------------------------------------------------- #

PS_PRELUDE = ("$ProgressPreference='SilentlyContinue';"
              "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
              "$OutputEncoding=[System.Text.Encoding]::UTF8;")


class Runner:
    def __init__(self, emit):
        self.emit = emit
        self.proc = None
        self.cancel_flag = threading.Event()
        self._last_empty = False

    def cancel(self):
        self.cancel_flag.set()
        p = self.proc
        if p and p.poll() is None:
            try:
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=CREATE_NO_WINDOW, timeout=10)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    def _emit_lines(self, buf):
        while True:
            m = re.search(r"\r\n|\n|\r", buf)
            if not m:
                return buf
            if m.group() == "\r" and m.end() == len(buf):
                return buf  # attendre de savoir si un \n suit
            line, sep, buf = buf[:m.start()], m.group(), buf[m.end():]
            prog = sep == "\r"
            if not line.strip():
                if prog or self._last_empty:
                    continue
                self._last_empty = True
            else:
                self._last_empty = False
            self.emit("console", ("   " + line.rstrip(), prog))

    def run(self, args, timeout=600, encoding=None, label=None, show=True):
        if self.cancel_flag.is_set():
            raise Cancelled()
        self.emit("console", ("» " + (label or " ".join(args)), False))
        try:
            p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
        except OSError as ex:
            self.emit("console", ("   ✖ impossible de lancer : %s" % ex, False))
            return -1, str(ex)
        self.proc = p
        q = queue.Queue()

        def reader():
            try:
                while True:
                    b = p.stdout.read1(65536) if hasattr(p.stdout, "read1") else p.stdout.read(4096)
                    if not b:
                        break
                    q.put(b)
            except Exception:
                pass
            q.put(None)

        threading.Thread(target=reader, daemon=True).start()
        parts, pending, dec = [], "", None
        start = time.time()
        timed_out = False
        while True:
            try:
                chunk = q.get(timeout=0.25)
            except queue.Empty:
                chunk = b""
            if chunk is None:
                break
            if chunk:
                if dec is None:
                    enc = encoding
                    if not enc:
                        zeros = chunk.count(b"\x00")
                        enc = "utf-16-le" if zeros > len(chunk) // 4 else oem_codec()
                    dec = codecs.getincrementaldecoder(enc)(errors="replace")
                s = dec.decode(chunk)
                if s.startswith("\ufeff"):
                    s = s[1:]
                parts.append(s)
                if show:
                    pending = self._emit_lines(pending + s)
            if self.cancel_flag.is_set():
                self.cancel()
                self.proc = None
                raise Cancelled()
            if timeout and time.time() - start > timeout:
                timed_out = True
                self.cancel()
                self.cancel_flag.clear()
                break
        if dec is not None:
            tail = dec.decode(b"", final=True)
            parts.append(tail)
            pending += tail
        if show and pending.strip():
            self._emit_lines(pending + "\n")
        try:
            rc = p.wait(timeout=10)
        except Exception:
            rc = -1
        self.proc = None
        if timed_out:
            self.emit("console", ("   ✖ délai dépassé (%ds), commande arrêtée" % timeout, False))
            rc = -2
        return rc, "".join(parts)

    def ps(self, script, timeout=300, label=None, show=True):
        enc = base64.b64encode((PS_PRELUDE + script).encode("utf-16-le")).decode("ascii")
        return self.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                         "-EncodedCommand", enc], timeout=timeout, encoding="utf-8",
                        label=label or ("PowerShell : " + script.strip().splitlines()[0][:90]), show=show)

    def ps_json(self, script, timeout=300, label=None):
        full = ("$__r = @(& {\n" + script + "\n});"
                "if ($__r.Count -eq 0) { '[]' } else { ConvertTo-Json -InputObject $__r -Depth 4 -Compress }")
        rc, out = self.ps(full, timeout=timeout, label=label, show=False)
        s = out.strip().lstrip("\ufeff")
        idx = [i for i in (s.find("["), s.find("{")) if i >= 0]
        if not idx:
            if s:
                self.emit("console", ("   " + s[:400], False))
            return []
        try:
            data = json.loads(s[min(idx):])
        except ValueError:
            self.emit("console", ("   ✖ réponse illisible : " + s[:300], False))
            return []
        if isinstance(data, dict):
            data = [data]
        self.emit("console", ("   %d élément(s)" % len(data), False))
        return data


# --------------------------------------------------------------------------- #
#  Moteur d'étapes
# --------------------------------------------------------------------------- #

SEV_ORDER = {"ok": 0, "info": 1, "warn": 2, "crit": 3}
SEV_LABEL = {"ok": "✔ OK", "info": "ℹ Info", "warn": "⚠ Attention", "crit": "✖ Critique"}


class Finding:
    _n = 0

    def __init__(self, sev, category, title, detail="", key=None):
        Finding._n += 1
        self.id = key or "f%d" % Finding._n
        self.sev, self.category, self.title, self.detail = sev, category, title, detail
        self.time = datetime.datetime.now()


class Step:
    def __init__(self, sid, title, kind, func, admin, confirm, menu):
        self.sid, self.title, self.kind, self.func = sid, title, kind, func
        self.admin, self.confirm, self.menu = admin, confirm, menu


STEPS = {}


def step(sid, title, kind="analysis", admin=False, confirm=None, menu=False):
    def deco(f):
        STEPS[sid] = Step(sid, title, kind, f, admin, confirm, menu)
        return f
    return deco


class Ctx:
    def __init__(self, engine, st):
        self.e, self.step = engine, st
        self.r = engine.runner
        self.state = engine.state
        self.findings = []

    def add(self, sev, title, detail="", category=None):
        f = Finding(sev, category or self.step.title, title, detail)
        self.findings.append(f)
        self.e.emit("finding", f)
        return f

    def queue(self, sid, force=False):
        self.e.enqueue(sid, force=force)

    def suggest(self, sid, reason):
        self.e.emit("suggest", (sid, reason))

    def suspect(self, name, pts, reason):
        s = self.state.setdefault("suspects", {}).setdefault(name, [0, []])
        s[0] += pts
        if reason not in s[1]:
            s[1].append(reason)

    def log(self, text):
        self.e.emit("console", ("   " + text, False))


class Engine:
    def __init__(self, emit):
        self.emit = emit
        self.runner = Runner(emit)
        self.state = {}
        self.q = []
        self.done = set()
        self.lock = threading.Lock()
        self.running = False

    def enqueue(self, sid, force=False):
        start = False
        with self.lock:
            if sid in self.q or (sid in self.done and not force):
                return
            self.q.append(sid)
            self.emit("step_status", (sid, "En attente", ""))
            if not self.running:
                self.running = True
                start = True
        if start:
            self.runner.cancel_flag.clear()
            threading.Thread(target=self._loop, daemon=True).start()

    def cancel(self):
        with self.lock:
            for sid in self.q:
                self.emit("step_status", (sid, "Annulé", ""))
            self.q = []
        self.runner.cancel()

    def reset(self):
        with self.lock:
            self.state.clear()
            self.done.clear()

    def _loop(self):
        self.emit("busy", True)
        while True:
            with self.lock:
                if not self.q:
                    self.running = False
                    if self.state.get("analysed"):
                        self.emit("finding", build_synthesis(self.state))
                    self.emit("busy", False)
                    return
                sid = self.q.pop(0)
            self._run(sid)

    def _run(self, sid):
        st = STEPS[sid]
        ctx = Ctx(self, st)
        self.emit("step_status", (sid, "En cours", ""))
        self.emit("console", ("", False))
        self.emit("console", ("━━ %s ━━" % st.title, False))
        t0 = time.time()
        status = "OK"
        try:
            if st.admin and IS_WIN and not is_admin():
                ctx.add("warn", "Droits administrateur requis",
                        "Cette étape a besoin des droits administrateur. Utilisez « Relancer en administrateur ».")
                ctx.suggest("__admin__", "Plusieurs analyses nécessitent les droits administrateur")
                status = "Ignoré"
            else:
                if st.kind == "analysis":
                    self.state["analysed"] = True
                st.func(ctx)
                worst = max([SEV_ORDER[f.sev] for f in ctx.findings] or [0])
                status = {0: "OK", 1: "OK", 2: "Attention", 3: "Problème"}[worst]
        except Cancelled:
            status = "Annulé"
            self.runner.cancel_flag.clear()
        except Exception as ex:
            ctx.add("warn", "Erreur interne : %s" % ex, traceback.format_exc())
            status = "Erreur"
        self.done.add(sid)
        self.emit("step_status", (sid, status, "%ds" % int(time.time() - t0)))


# --------------------------------------------------------------------------- #
#  Étapes d'analyse
# --------------------------------------------------------------------------- #

@step("sysinfo", "Informations système")
def s_sysinfo(c):
    data = c.r.ps_json(r"""
$os=Get-CimInstance Win32_OperatingSystem; $cs=Get-CimInstance Win32_ComputerSystem
$bb=Get-CimInstance Win32_BaseBoard; $bios=Get-CimInstance Win32_BIOS
$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1
$gpu=Get-CimInstance Win32_VideoController
$pend = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
[pscustomobject]@{
  OS=$os.Caption; Build="$($os.Version)"; Boot=$os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')
  UptimeH=[math]::Round(((Get-Date)-$os.LastBootUpTime).TotalHours,1)
  CPU="$($cpu.Name)".Trim(); Board="$($bb.Manufacturer) $($bb.Product)"
  BIOS="$($bios.SMBIOSBIOSVersion)"; BIOSDate=$bios.ReleaseDate.ToString('yyyy-MM-dd')
  RAMGB=[math]::Round($cs.TotalPhysicalMemory/1GB,1)
  GPU=(($gpu | ForEach-Object { "$($_.Name) (pilote $($_.DriverVersion), $(if($_.DriverDate){$_.DriverDate.ToString('yyyy-MM-dd')}))" }) -join ' | ')
  PendingReboot=[bool]$pend
}""", label="Lecture de la configuration")
    if not data:
        c.add("warn", "Impossible de lire la configuration")
        return
    d = data[0]
    c.state["sysinfo"] = d
    c.add("info", "%s — %s" % (d.get("CPU"), d.get("Board")),
          "Windows : %s (%s)\nCPU : %s\nCarte mère : %s\nBIOS : %s du %s\nRAM : %s Go\nGPU : %s\n"
          "Démarré le %s (depuis %s h)" % (d.get("OS"), d.get("Build"), d.get("CPU"), d.get("Board"), d.get("BIOS"),
                                          d.get("BIOSDate"), d.get("RAMGB"), d.get("GPU"), d.get("Boot"), d.get("UptimeH")))
    try:
        bdate = datetime.datetime.strptime(d.get("BIOSDate", ""), "%Y-%m-%d")
        age = (datetime.datetime.now() - bdate).days
        if age > 730:
            c.add("info", "BIOS ancien (%d ans)" % (age // 365),
                  "Le BIOS date du %s. Les mises à jour BIOS améliorent souvent la stabilité mémoire (AGESA chez AMD). "
                  "À envisager si les plantages persistent." % d.get("BIOSDate"))
    except ValueError:
        pass
    if d.get("PendingReboot"):
        c.add("warn", "Un redémarrage est en attente",
              "Windows attend un redémarrage pour finir une mise à jour. Certaines réparations (SFC/DISM) peuvent échouer avant.")


@step("crashes", "Historique des plantages")
def s_crashes(c):
    events = c.r.ps_json(r"""
Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,6008,1001; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue |
 Where-Object { $_.Id -ne 1001 -or $_.ProviderName -match 'WER-SystemErrorReporting|BugCheck' } |
 Select-Object @{n='Time';e={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, Id, ProviderName,
   @{n='Msg';e={$_.Message}}, @{n='P';e={ (@($_.Properties | ForEach-Object { "$($_.Value)" })) -join '|' }}
""", label="Événements de plantage (30 jours)")
    bugchecks, hard = [], []
    for ev in events:
        if ev.get("Id") == 1001:
            code, params, dump = parse_bugcheck_message(ev.get("Msg") or "")
            if code is not None:
                bugchecks.append((ev.get("Time"), code, params, dump))
        elif ev.get("Id") == 41 and "Kernel-Power" in (ev.get("ProviderName") or ""):
            p = ev.get("P") or ""
            if isinstance(p, dict):  # PowerShell 5.1 : tableau sérialisé en {"value": [...], "Count": n}
                p = p.get("value") or []
            if isinstance(p, str):
                p = p.split("|")
            try:
                bc = int(p[0]) if p else 0
            except ValueError:
                bc = 0
            if bc == 0:
                power_btn = len(p) > 6 and p[6] not in ("0", "", None)
                hard.append((ev.get("Time"), power_btn))
    c.state["bugchecks"] = bugchecks

    if not bugchecks and not hard:
        c.add("ok", "Aucun plantage système sur les 30 derniers jours")
    codes = set()
    for t, code, params, dump in bugchecks:
        codes.add(code)
        name, expl = bugcheck_label(code)
        c.add("crit", "Écran bleu 0x%X %s — %s" % (code, name, t),
              "%s\n\nParamètres : %s\nVidage : %s" % (expl, ", ".join(params), dump or "non indiqué"))
        if code == 0x124:
            c.suspect("Matériel (CPU / overclock / alimentation)", 5, "écran bleu WHEA 0x124")
        elif code in (0x101,):
            c.suspect("Matériel (CPU / overclock / alimentation)", 4, "CLOCK_WATCHDOG_TIMEOUT")
        elif code in (0x116, 0x117, 0x119):
            c.suspect("Pilote graphique / GPU", 4, "plantage GPU 0x%X" % code)
        elif code in (0x7A, 0x154):
            c.suspect("Disque / stockage", 3, "erreur de lecture disque 0x%X" % code)
        if code in RAM_HINT_CODES:
            c.suspect("RAM instable", 1, "code 0x%X compatible avec une RAM instable" % code)
    if len(codes) >= 2:
        c.add("warn", "%d codes d'écran bleu différents" % len(codes),
              "Des codes d'erreur variés d'un plantage à l'autre sont la signature classique d'une RAM instable "
              "(ou d'un overclock instable).")
        c.suspect("RAM instable", 4, "codes d'écran bleu différents à chaque plantage")
    for t, power_btn in hard:
        if any(abs(_ts(t) - _ts(b[0])) < 120 for b in bugchecks):
            continue
        if power_btn:
            c.add("warn", "Arrêt forcé au bouton (gel) — %s" % t,
                  "Le PC a été éteint en maintenant le bouton : il était probablement gelé.")
            c.suspect("Gel système (pilote, GPU, RAM)", 2, "gel avec arrêt forcé le %s" % t)
        else:
            c.add("crit", "Coupure brutale sans écran bleu — %s" % t,
                  "Le PC s'est éteint/redémarré sans pouvoir enregistrer d'erreur : coupure d'alimentation, "
                  "bloc d'alimentation, surchauffe, ou instabilité CPU/RAM sévère.")
            c.suspect("Alimentation / surchauffe", 3, "redémarrage brutal sans écran bleu le %s" % t)

    dumps = find_dumps()
    c.state["dumps"] = dumps
    if dumps:
        c.log("Vidages trouvés : " + ", ".join(os.path.basename(d) for d in dumps[:5]))
        c.queue("dump_analysis")
    elif bugchecks:
        c.add("info", "Aucun fichier de vidage accessible",
              "Les vidages sont peut-être illisibles sans droits administrateur, ou ont été supprimés.")


def _ts(s):
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S").timestamp()
    except (TypeError, ValueError):
        return 0


def find_dumps():
    files = []
    for d in ("Minidump", "Minidumps"):
        try:
            for f in os.listdir(os.path.join(SYSROOT, d)):
                if f.lower().endswith(".dmp"):
                    files.append(os.path.join(SYSROOT, d, f))
        except OSError:
            pass
    big = os.path.join(SYSROOT, "MEMORY.DMP")
    if os.path.exists(big):
        files.append(big)
    files.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0, reverse=True)
    return files


def find_cdb(r):
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pfx = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    cands = sorted(glob.glob(os.path.join(pf, "WindowsApps", "Microsoft.WinDbg_*", "amd64", "cdb.exe")), reverse=True)
    cands += [os.path.join(pfx, "Windows Kits", "10", "Debuggers", "x64", "cdb.exe")]
    for cnd in cands:
        if os.path.isfile(cnd):
            return cnd
    data = r.ps_json(r'Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.WinDbg_*\amd64\cdb.exe" -ErrorAction SilentlyContinue |'
                     r' Sort-Object LastWriteTime -Descending | Select-Object -First 1 FullName',
                     label="Recherche du débogueur (cdb)")
    if data and data[0].get("FullName"):
        return data[0]["FullName"]
    return None


@step("dump_analysis", "Analyse des vidages mémoire", admin=True)
def s_dump(c):
    dumps = []
    manual = c.state.pop("manual_dump", None)
    if manual:
        dumps = [manual]
    else:
        dumps = (c.state.get("dumps") or find_dumps())[:3]
    if not dumps:
        c.add("ok", "Aucun vidage mémoire à analyser")
        return
    cdb = find_cdb(c.r)
    if not cdb:
        c.add("warn", "Débogueur WinDbg absent",
              "Pour savoir quel pilote a provoqué l'écran bleu, il faut le débogueur officiel Microsoft (WinDbg).")
        c.suggest("install_windbg", "Nécessaire pour identifier le pilote responsable des écrans bleus")
        return
    sym_root = r"C:\symbols" if os.path.isdir(r"C:\symbols") else os.path.join(
        os.environ.get("LOCALAPPDATA", SYSROOT), "PCDoctor", "symbols")
    symp = "srv*%s*https://msdl.microsoft.com/download/symbols" % sym_root
    all_ms = True
    for dmp in dumps:
        c.log("Analyse de %s (le 1er passage télécharge les symboles, ~1-3 min)" % dmp)
        rc, out = c.r.run([cdb, "-z", dmp, "-y", symp, "-c", "!analyze -v; .echo ===KN===; kn 40; q"],
                          timeout=900, label="cdb !analyze -v %s" % os.path.basename(dmp), show=False)
        res = parse_cdb(out)
        if not res.get("MODULE_NAME") and not res.get("FAILURE_BUCKET_ID"):
            c.add("warn", "Analyse impossible : %s" % os.path.basename(dmp), out[-1500:])
            continue
        if "===KN===" in out:
            kn = parse_cdb(out.split("===KN===", 1)[1])
            for m in kn["STACK"]:
                if m not in res["STACK"]:
                    res["STACK"].append(m)
        try:
            code = int(res.get("BUGCHECK_CODE", "0"), 16)
        except ValueError:
            code = 0
        name, expl = bugcheck_label(code)
        culprits = third_party_modules([res.get("IMAGE_NAME", ""), res.get("MODULE_NAME", "")] + res["STACK"])
        bucket = res.get("FAILURE_BUCKET_ID", "")
        lines = ["Code : 0x%X %s" % (code, name), "Module : %s (%s)" % (res.get("MODULE_NAME"), res.get("IMAGE_NAME")),
                 "Fonction : %s" % res.get("SYMBOL_NAME", "?"), "Processus : %s" % res.get("PROCESS_NAME", "?"),
                 "Bucket : %s" % bucket, "Pile : %s" % " → ".join(res["STACK"]), ""]
        if culprits:
            all_ms = False
            desc = ", ".join("%s.sys (%s)" % (m, KNOWN_DRIVERS.get(m, "pilote tiers")) for m in culprits)
            lines.append("Pilote(s) non-Microsoft impliqué(s) : " + desc)
            lines.append("→ Mettre à jour ou désinstaller ce logiciel/pilote est la piste n°1.")
            c.add("crit", "%s : pilote tiers en cause → %s" % (os.path.basename(dmp), culprits[0]), "\n".join(lines))
            c.suspect("Pilote %s (%s)" % (culprits[0], KNOWN_DRIVERS.get(culprits[0], "tiers")), 6,
                      "présent dans la pile du vidage %s" % os.path.basename(dmp))
        else:
            lines.append("Seuls des modules Microsoft apparaissent : Windows est la VICTIME d'une corruption "
                         "survenue plus tôt. Causes typiques : RAM instable (XMP/EXPO, barrettes mélangées), "
                         "pilote tiers qui écrase la mémoire sans laisser de trace, ou fichiers système corrompus.")
            c.add("warn", "%s : %s dans %s, aucun pilote tiers" % (os.path.basename(dmp), name, res.get("MODULE_NAME")),
                  "\n".join(lines))
            c.suspect("RAM instable", 3, "vidage %s : pile 100 %% Microsoft (corruption mémoire)" % os.path.basename(dmp))
        if "memory_corruption" in bucket.lower() or "MEMORY_CORRUPTION" in out:
            c.suspect("RAM instable", 5, "le débogueur signale une corruption mémoire")
        if res.get("MODULE_NAME", "").lower() in ("ntfs", "refs") or any(m.lower() == "ntfs" for m in res["STACK"]):
            c.queue("sfc_verify")
            c.queue("volume_scan")
            c.queue("disks")
    if all_ms:
        c.queue("ram")


@step("whea", "Erreurs matérielles (WHEA)")
def s_whea(c):
    ev = c.r.ps_json(r"""
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue |
 Select-Object @{n='Time';e={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, Id, @{n='Msg';e={$_.Message}}""",
                     label="Journal WHEA-Logger (30 jours)")
    if not ev:
        c.add("ok", "Aucune erreur matérielle remontée par le CPU / PCIe")
        return
    by = {}
    for e in ev:
        by.setdefault(e.get("Id"), []).append(e)
    for i, lst in by.items():
        first = (lst[0].get("Msg") or "")[:900]
        if i == 17:
            c.add("warn", "%d erreur(s) PCIe corrigée(s) (ID 17)" % len(lst),
                  "Une carte PCIe ou un SSD NVMe génère des erreurs de liaison. Vérifier les cartes ajoutées, "
                  "le slot utilisé, et forcer la génération PCIe (Gen3) dans le BIOS si besoin.\n\n" + first)
            c.suspect("Matériel PCIe (carte, slot, SSD)", 3, "%d erreurs WHEA PCIe" % len(lst))
        elif i == 19:
            c.add("warn", "%d erreur(s) CPU/cache corrigée(s) (ID 19)" % len(lst),
                  "Typique d'un CPU instable : overclock, PBO, Curve Optimizer, undervolt ou tension trop basse.\n\n" + first)
            c.suspect("Matériel (CPU / overclock / alimentation)", 4, "%d erreurs WHEA CPU" % len(lst))
        elif i in (1, 18, 20, 46, 47):
            c.add("crit", "%d erreur(s) matérielle(s) fatale(s) (ID %s)" % (len(lst), i), first)
            c.suspect("Matériel (CPU / overclock / alimentation)", 5, "erreur WHEA fatale")
        else:
            c.add("warn", "%d événement(s) WHEA (ID %s)" % (len(lst), i), first)


@step("ram", "Mémoire vive (RAM)")
def s_ram(c):
    mods = c.r.ps_json(r"""
Get-CimInstance Win32_PhysicalMemory | Select-Object BankLabel, DeviceLocator, Manufacturer,
 @{n='Part';e={"$($_.PartNumber)".Trim()}}, @{n='GB';e={[math]::Round($_.Capacity/1GB)}},
 Speed, ConfiguredClockSpeed, SMBIOSMemoryType, ConfiguredVoltage""", label="Barrettes installées")
    if not mods:
        c.add("warn", "Impossible de lire la configuration mémoire")
        return
    lines, kits = [], set()
    ddr = "DDR4"
    maxspd = 0
    for m in mods:
        part = (m.get("Part") or "").strip()
        manu = (m.get("Manufacturer") or "").strip()
        ident = part or manu or "?"
        kits.add(ident.upper())
        spd = m.get("ConfiguredClockSpeed") or m.get("Speed") or 0
        maxspd = max(maxspd, spd or 0)
        if m.get("SMBIOSMemoryType") == 34:
            ddr = "DDR5"
        lines.append("%-14s %-8s %-18s %-22s %3s Go  %s MHz" % (m.get("BankLabel"), m.get("DeviceLocator"),
                                                               manu[:18], part[:22], m.get("GB"), spd))
    detail = "\n".join(lines)
    jedec = 4800 if ddr == "DDR5" else 2666
    xmp = maxspd > jedec
    n = len(mods)
    c.state["ram"] = {"n": n, "mixed": len(kits) > 1, "xmp": xmp, "speed": maxspd}
    c.add("info", "%d barrette(s) %s à %s MHz%s" % (n, ddr, maxspd, " (profil XMP/EXPO actif)" if xmp else ""), detail)
    if len(kits) > 1:
        sev = "crit" if xmp else "warn"
        c.add(sev, "Barrettes de kits/marques différents mélangées",
              "Références détectées : %s\n\nDes barrettes qui ne viennent pas du même kit ne sont pas validées ensemble. "
              "%s\n\nTests recommandés :\n"
              "  1. Garder un seul kit (2 barrettes identiques) avec XMP/EXPO → si plus de plantage, c'était ça.\n"
              "  2. Ou garder tout mais désactiver XMP/EXPO (ou baisser la fréquence, augmenter légèrement la tension DRAM).\n"
              "  3. Confirmer avec MemTest86 (clé USB, 4 passes) ou le diagnostic mémoire Windows."
              % (", ".join(sorted(kits)),
                 "Avec XMP/EXPO activé, c'est l'une des premières causes de plantages aléatoires et de fichiers corrompus."
                 if xmp else ""))
        c.suspect("RAM instable", 5 if xmp else 3, "kits de RAM différents mélangés%s" % (" en XMP/EXPO" if xmp else ""))
    if n >= 4 and xmp:
        c.add("warn", "4 barrettes en XMP/EXPO",
              "4 barrettes chargent davantage le contrôleur mémoire : le profil XMP/EXPO, validé pour 2 barrettes, "
              "est souvent instable avec 4.")
        c.suspect("RAM instable", 1, "4 barrettes avec XMP/EXPO")
    c.suggest("memtest", "Tester la RAM (diagnostic mémoire Windows au prochain redémarrage)")
    res = c.r.ps_json(r"""
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-MemoryDiagnostics-Results'} -MaxEvents 3 -ErrorAction SilentlyContinue |
 Select-Object @{n='Time';e={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm')}}, Id, @{n='Msg';e={$_.Message}}""",
                      label="Résultats du diagnostic mémoire Windows")
    for e in res[:1]:
        msg = norm(e.get("Msg"))
        if "aucune erreur" in msg or "no errors" in msg:
            c.add("info", "Diagnostic mémoire Windows du %s : aucune erreur" % e.get("Time"),
                  "Ce test est assez léger : il ne garantit pas une RAM stable sous XMP. MemTest86 est plus fiable.")
        else:
            c.add("crit", "Diagnostic mémoire Windows du %s : ERREURS détectées" % e.get("Time"), e.get("Msg") or "")
            c.suspect("RAM instable", 8, "le diagnostic mémoire Windows a trouvé des erreurs")


@step("disks", "Santé des disques")
def s_disks(c):
    disks = c.r.ps_json(r"""
Get-PhysicalDisk | ForEach-Object {
  $r = $_ | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
  [pscustomobject]@{ Name=$_.FriendlyName; Media="$($_.MediaType)"; Bus="$($_.BusType)"; Health="$($_.HealthStatus)";
    Op=(@($_.OperationalStatus) -join ','); SizeGB=[math]::Round($_.Size/1GB); Temp=$r.Temperature; Wear=$r.Wear;
    RErr=$r.ReadErrorsUncorrected; WErr=$r.WriteErrorsUncorrected; Hours=$r.PowerOnHours } }""",
                        label="État des disques physiques")
    for d in disks:
        info = "Type : %s %s, %s Go\nÉtat : %s / %s\nTempérature : %s °C\nUsure : %s %%\nHeures : %s\n" \
               "Erreurs lecture/écriture non corrigées : %s / %s" % (
                   d.get("Media"), d.get("Bus"), d.get("SizeGB"), d.get("Health"), d.get("Op"), d.get("Temp"),
                   d.get("Wear"), d.get("Hours"), d.get("RErr"), d.get("WErr"))
        bad = d.get("Health") not in ("Healthy", "Sain") or (d.get("RErr") or 0) > 0 or (d.get("WErr") or 0) > 0
        hot = (d.get("Temp") or 0) >= 70
        worn = (d.get("Wear") or 0) >= 80
        if bad:
            c.add("crit", "%s : disque en mauvaise santé" % d.get("Name"), info)
            c.suspect("Disque / stockage", 6, "%s signalé en mauvaise santé" % d.get("Name"))
        elif hot or worn:
            c.add("warn", "%s : %s" % (d.get("Name"), "trop chaud" if hot else "usure élevée"), info)
        else:
            c.add("ok", "%s : sain" % d.get("Name"), info + (
                "\n\n(Compteurs d'erreurs vides : normal pour beaucoup de NVMe. CrystalDiskInfo lit le SMART complet.)"
                if d.get("RErr") is None else ""))
    vols = c.r.ps_json(r"""
Get-Volume | Where-Object { $_.DriveLetter -and $_.Size -gt 0 } | Select-Object DriveLetter, FileSystemLabel,
 @{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,1)}}, @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}}""",
                       label="Espace libre des volumes")
    for v in vols:
        size, free = v.get("SizeGB") or 0, v.get("FreeGB") or 0
        if size and free / size < 0.10:
            c.add("warn", "Volume %s: presque plein (%s Go libres sur %s)" % (v.get("DriveLetter"), free, size),
                  "Moins de 10 % d'espace libre : Windows Update, le fichier d'échange et les vidages mémoire peuvent échouer.")
            c.suggest("cleanmgr", "Libérer de l'espace sur %s:" % v.get("DriveLetter"))
    ev = c.r.ps_json(r"""
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='disk','Ntfs','stornvme','storahci','volmgr'; Level=1,2,3; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue |
 Where-Object { $_.Id -in 7,11,15,51,129,153,55,98,130,140,157 } |
 Select-Object @{n='Time';e={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm')}}, Id, ProviderName, @{n='Msg';e={$_.Message}}""",
                     label="Erreurs disque/NTFS dans le journal (30 jours)")
    if ev:
        sample = "\n\n".join("%s  %s %s\n%s" % (e.get("Time"), e.get("ProviderName"), e.get("Id"),
                                                (e.get("Msg") or "")[:300]) for e in ev[:6])
        c.add("warn", "%d erreur(s) disque/NTFS dans le journal" % len(ev), sample)
        c.suspect("Disque / stockage", 2 if len(ev) < 5 else 4, "%d erreurs disque/NTFS" % len(ev))
        c.queue("volume_scan")


@step("volume_scan", "Système de fichiers (scan NTFS)", admin=True)
def s_volume_scan(c):
    rc, out = c.r.ps("Repair-Volume -DriveLetter %s -Scan" % SYSDRIVE, timeout=3600,
                     label="Repair-Volume -DriveLetter %s -Scan (lecture seule)" % SYSDRIVE)
    o = out.lower()
    if "noerrorsfound" in o:
        c.add("ok", "Système de fichiers %s: sans erreur" % SYSDRIVE)
    elif "spotfixneeded" in o:
        c.add("crit", "Erreurs NTFS détectées sur %s:" % SYSDRIVE,
              "Le scan a trouvé des erreurs réparables rapidement (SpotFix).")
        c.suspect("Système de fichiers corrompu", 3, "erreurs NTFS détectées")
        c.suggest("spotfix", "Corriger les erreurs NTFS détectées sur %s:" % SYSDRIVE)
    elif "scanneeded" in o or "fullrepairneeded" in o:
        c.add("crit", "Le volume %s: nécessite une réparation complète" % SYSDRIVE, out.strip()[-1000:])
        c.suspect("Système de fichiers corrompu", 4, "réparation complète du volume nécessaire")
        c.suggest("offline_fix", "Réparation complète du volume %s: (au redémarrage)" % SYSDRIVE)
    else:
        c.add("warn", "Scan du volume impossible ou résultat inattendu",
              (out.strip()[-1500:] or "(aucune sortie)") +
              "\n\nSi « Accès refusé » : un logiciel tiers peut bloquer chkdsk. Ce n'est pas bloquant pour le reste du diagnostic.")


@step("sfc_verify", "Fichiers système (vérification)", admin=True)
def s_sfc_verify(c):
    rc, out = c.r.run([sys32("sfc.exe"), "/verifyonly"], timeout=3600, label="sfc /verifyonly (lecture seule)")
    st = parse_sfc(out)
    if st == "ok":
        c.add("ok", "Fichiers système intacts")
    elif st in ("found", "unrepaired"):
        c.add("crit", "Fichiers système corrompus détectés",
              "SFC a trouvé des fichiers Windows modifiés/corrompus. Réparation : DISM (récupère des copies saines "
              "sur Windows Update) puis SFC /scannow.")
        c.suspect("Fichiers système corrompus", 3, "SFC a détecté des violations d'intégrité")
        c.queue("cbs_log", force=True)
        c.suggest("dism_restore", "Réparer les fichiers système (DISM puis SFC)")
    elif st == "noadmin":
        c.add("warn", "SFC exige les droits administrateur")
    else:
        c.add("warn", "Vérification SFC impossible (%s)" % st, out.strip()[-1200:])


@step("cbs_log", "Journal CBS (fichiers en cause)")
def s_cbs(c):
    path = os.path.join(SYSROOT, "Logs", "CBS", "CBS.log")
    text = ""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 12 * 1024 * 1024))
            text = fh.read().decode("utf-8", "replace")
    except OSError:
        rc, text = c.r.ps("Get-Content -Path '%s' -Tail 40000" % path, label="Lecture de CBS.log", show=False)
    if not text:
        c.add("info", "Journal CBS illisible")
        return
    cannot, repaired, store = parse_cbs(last_sfc_session(text))
    if cannot:
        c.add("crit", "Fichier(s) non réparable(s) : %s" % ", ".join(cannot[:6]),
              "Fichiers : %s\n\n%s" % (", ".join(cannot),
                                       "La copie de secours (magasin WinSxS) est aussi corrompue : SFC seul ne peut pas réparer. "
                                       "DISM /RestoreHealth récupère des copies saines sur Windows Update."
                                       if store else ""))
        c.suggest("dism_restore", "Le magasin de composants est corrompu : DISM puis SFC")
        if store:
            c.suspect("RAM instable", 1, "original ET copie de secours corrompus (écriture corrompue ?)")
    if repaired:
        c.add("ok", "Fichier(s) réparé(s) par SFC : %s" % ", ".join(repaired[:8]))
    if not cannot and not repaired:
        c.add("ok", "Aucune corruption mentionnée dans la dernière session SFC")


@step("drivers", "Pilotes tiers chargés")
def s_drivers(c):
    sysd = c.r.ps_json(r"""
Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' } | Select-Object Name, DisplayName, PathName""",
                       label="Pilotes noyau en cours d'exécution")
    found = []
    for d in sysd:
        base = os.path.splitext(os.path.basename((d.get("PathName") or "").strip('"')))[0].lower()
        if base in KNOWN_DRIVERS:
            found.append("%s.sys — %s" % (base, KNOWN_DRIVERS[base]))
    c.state["loaded_known"] = found
    if found:
        c.add("info", "%d pilote(s) tiers notable(s) chargé(s)" % len(found),
              "\n".join(found) + "\n\nCes pilotes sont légitimes mais fréquemment impliqués dans des écrans bleus. "
              "Si un vidage les désigne, les mettre à jour ou désinstaller le logiciel associé.")
    risky = [f for f in found if f.split(".")[0] in ("winring0x64", "asio2", "asio3", "asusgio2", "gdrv2", "gdrv3", "cpuz")]
    if risky:
        c.add("warn", "Utilitaires bas niveau détectés",
              "\n".join(risky) + "\n\nLes utilitaires constructeur (GPU Tweak, App Center, RGB…) installent des pilotes "
              "qui accèdent directement au matériel. Désinstaller ceux qui ne servent pas réduit les risques.")
        c.suspect("Utilitaires bas niveau (RGB/OC constructeur)", 1, "pilotes d'accès direct au matériel chargés")
    pnp = c.r.ps_json(r"""
Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DriverProviderName -and $_.DriverProviderName -notmatch 'Microsoft' -and $_.DeviceClass -in 'DISPLAY','NET','MEDIA','SCSIADAPTER','HDC','SYSTEM' } |
 Select-Object DeviceName, DeviceClass, DriverProviderName, DriverVersion, @{n='Date';e={ if($_.DriverDate){$_.DriverDate.ToString('yyyy-MM-dd')} }} |
 Sort-Object Date -Descending""", label="Pilotes de périphériques non-Microsoft")
    if pnp:
        old = [p for p in pnp if p.get("DeviceClass") in ("DISPLAY", "NET") and p.get("Date") and p["Date"] < (
            datetime.date.today() - datetime.timedelta(days=540)).isoformat()]
        c.add("info", "%d pilote(s) de périphériques non-Microsoft" % len(pnp),
              "\n".join("%s | %s | %s | %s | %s" % (p.get("Date"), p.get("DeviceClass"), p.get("DeviceName"),
                                                   p.get("DriverProviderName"), p.get("DriverVersion")) for p in pnp[:30]))
        for p in old:
            c.add("info", "Pilote ancien : %s (%s)" % (p.get("DeviceName"), p.get("Date")),
                  "Un pilote graphique ou réseau de plus de 18 mois mérite une mise à jour depuis le site du fabricant.")


@step("filters", "Pilotes filtres de fichiers", admin=True)
def s_filters(c):
    rc, out = c.r.run([sys32("fltmc.exe")], timeout=60, label="fltmc", show=True)
    names = parse_fltmc(out)
    if not names:
        c.add("warn", "Liste des filtres illisible", out[-600:])
        return
    third = [n for n in names if n.lower() not in MS_FILTERS]
    if third:
        c.add("warn", "%d filtre(s) tiers sur le système de fichiers" % len(third),
              "Filtres non-Microsoft : %s\n\nAntivirus, sauvegarde, synchronisation ou anti-triche s'insèrent ici. "
              "Un filtre bogué peut corrompre la mémoire NTFS." % ", ".join(third))
        for t in third:
            c.suspect("Filtre de fichiers %s" % t, 1, "filtre tiers actif")
    else:
        c.add("ok", "Uniquement des filtres Microsoft (%d)" % len(names), ", ".join(names))


@step("defender", "Protection antivirus")
def s_defender(c):
    st = c.r.ps_json(r"""
$s = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($s) { [pscustomobject]@{ RT=$s.RealTimeProtectionEnabled; AV=$s.AntivirusEnabled; Sig=$s.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd') } }""",
                     label="État de Microsoft Defender")
    if st:
        s = st[0]
        if s.get("RT") and s.get("AV"):
            c.add("ok", "Defender actif (signatures du %s)" % s.get("Sig"))
        else:
            c.add("info", "Defender désactivé ou remplacé par un autre antivirus")
    th = c.r.ps_json(r"""
Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending | Select-Object -First 5 @{n='Time';e={$_.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm')}}, @{n='Res';e={ @($_.Resources) -join '; ' }}""",
                     label="Menaces détectées récemment")
    if th:
        c.add("warn", "%d détection(s) récente(s) par Defender" % len(th),
              "\n".join("%s  %s" % (t.get("Time"), (t.get("Res") or "")[:200]) for t in th))


@step("dism_scan", "Magasin de composants (DISM ScanHealth)", admin=True, menu=True)
def s_dism_scan(c):
    rc, out = c.r.run([sys32("dism.exe"), "/Online", "/Cleanup-Image", "/ScanHealth"], timeout=3600,
                      label="DISM /Online /Cleanup-Image /ScanHealth (lecture seule)")
    st = parse_dism(out)
    if st == "clean":
        c.add("ok", "Magasin de composants sain")
    elif st == "repairable":
        c.add("crit", "Magasin de composants corrompu (réparable)")
        c.suggest("dism_restore", "Réparer le magasin de composants")
    else:
        c.add("warn", "Résultat DISM : %s" % st, out.strip()[-1000:])


# --------------------------------------------------------------------------- #
#  Réparations / maintenance (toujours sur confirmation)
# --------------------------------------------------------------------------- #

@step("restore_point", "Créer un point de restauration", kind="repair", admin=True, menu=True,
      confirm="Créer un point de restauration système maintenant ?\n\n(Windows en autorise un par 24 h ; "
              "la protection du système doit être activée sur C:.)")
def r_restore_point(c):
    rc, out = c.r.ps("Checkpoint-Computer -Description 'PC Doctor' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop; 'OK'",
                     timeout=600, label="Checkpoint-Computer")
    if out.strip().endswith("OK"):
        c.add("ok", "Point de restauration créé")
    else:
        c.add("warn", "Point de restauration non créé", out.strip()[-800:])


@step("dism_restore", "Réparer les fichiers système (DISM + SFC)", kind="repair", admin=True, menu=True,
      confirm="Lancer la réparation des fichiers système ?\n\n1. DISM /RestoreHealth télécharge des copies saines "
              "depuis Windows Update (10-20 min).\n2. SFC /scannow remplace ensuite les fichiers corrompus.\n\n"
              "Vos documents et logiciels ne sont pas touchés.")
def r_dism(c):
    rc, out = c.r.run([sys32("dism.exe"), "/Online", "/Cleanup-Image", "/RestoreHealth"], timeout=7200,
                      label="DISM /Online /Cleanup-Image /RestoreHealth")
    st = parse_dism(out)
    if st in ("restored", "success", "clean"):
        c.add("ok", "DISM : magasin de composants réparé")
        c.queue("sfc_scannow", force=True)
    elif st == "nosource":
        c.add("crit", "DISM n'a pas trouvé de fichiers sources (0x800f081f)",
              "Windows Update n'a pas fourni les fichiers. Solution : monter une ISO de la même version de Windows "
              "et relancer DISM avec /Source:WIM:X:\\sources\\install.wim:1 /LimitAccess.")
    else:
        c.add("warn", "DISM a échoué (%s)" % st, out.strip()[-1500:])


@step("sfc_scannow", "SFC /scannow (réparation)", kind="repair", admin=True, menu=True,
      confirm="Lancer sfc /scannow ? Il remplace les fichiers système corrompus (10-15 min).")
def r_sfc(c):
    rc, out = c.r.run([sys32("sfc.exe"), "/scannow"], timeout=3600, label="sfc /scannow")
    st = parse_sfc(out)
    if st == "ok":
        c.add("ok", "SFC : aucune violation d'intégrité")
    elif st == "repaired":
        c.add("ok", "SFC : fichiers corrompus réparés")
        c.queue("cbs_log", force=True)
    elif st == "unrepaired":
        c.add("crit", "SFC n'a pas pu tout réparer")
        c.queue("cbs_log", force=True)
        c.suggest("dism_restore", "SFC n'a pas pu tout réparer : DISM d'abord")
    else:
        c.add("warn", "Résultat SFC : %s" % st, out.strip()[-1200:])


@step("spotfix", "Corriger les erreurs NTFS (SpotFix)", kind="repair", admin=True, menu=True,
      confirm="Corriger les erreurs NTFS détectées (Repair-Volume -SpotFix) ?\n\nSur le disque système, "
              "la correction peut nécessiter un redémarrage (quelques secondes au démarrage).")
def r_spotfix(c):
    rc, out = c.r.ps("Repair-Volume -DriveLetter %s -SpotFix" % SYSDRIVE, timeout=3600,
                     label="Repair-Volume -DriveLetter %s -SpotFix" % SYSDRIVE)
    c.add("info", "SpotFix : %s" % (out.strip().splitlines()[-1] if out.strip() else "terminé"), out.strip()[-1000:])


@step("offline_fix", "Réparation complète du volume (au redémarrage)", kind="repair", admin=True,
      confirm="Programmer une réparation complète du volume système ?\n\nElle s'exécutera au prochain redémarrage "
              "et peut durer de quelques minutes à plus d'une heure.")
def r_offline(c):
    rc, out = c.r.ps("Repair-Volume -DriveLetter %s -OfflineScanAndFix" % SYSDRIVE, timeout=600,
                     label="Repair-Volume -OfflineScanAndFix")
    c.add("info", "Réparation programmée au prochain redémarrage", out.strip()[-800:])


@step("install_windbg", "Installer WinDbg (analyse des écrans bleus)", kind="repair", menu=True,
      confirm="Installer le débogueur officiel Microsoft WinDbg via winget ?\n\nIl sert uniquement à lire les "
              "fichiers de vidage pour identifier le pilote responsable.")
def r_windbg(c):
    rc, out = c.r.run(["winget", "install", "--id", "Microsoft.WinDbg", "-e",
                       "--accept-source-agreements", "--accept-package-agreements"], timeout=1800,
                      encoding="utf-8", label="winget install Microsoft.WinDbg")
    if find_cdb(c.r):
        c.add("ok", "WinDbg installé")
        c.queue("dump_analysis", force=True)
    else:
        c.add("warn", "Installation de WinDbg non confirmée", out.strip()[-1000:])


@step("memtest", "Diagnostic mémoire Windows", kind="repair", menu=True,
      confirm="Ouvrir l'outil de diagnostic mémoire Windows ?\n\nIl vous proposera de redémarrer maintenant ou au "
              "prochain démarrage. Le résultat sera lu par PC Doctor au prochain diagnostic.\n\n"
              "Pour un test plus poussé : MemTest86 sur clé USB, 4 passes minimum.")
def r_memtest(c):
    subprocess.Popen([sys32("mdsched.exe")], creationflags=0)
    c.add("info", "Outil de diagnostic mémoire ouvert", "Choisissez « Redémarrer maintenant » ou « au prochain démarrage ».")


@step("cleanmgr", "Nettoyage de disque", kind="repair", menu=True,
      confirm="Ouvrir le nettoyage de disque Windows ? Vous choisirez vous-même quoi supprimer.")
def r_cleanmgr(c):
    subprocess.Popen([sys32("cleanmgr.exe")], creationflags=0)
    c.add("info", "Nettoyage de disque ouvert")


@step("component_cleanup", "Nettoyer les anciennes versions de mises à jour", kind="repair", admin=True, menu=True,
      confirm="Supprimer les anciennes versions des composants Windows remplacés par des mises à jour ?\n\n"
              "Libère de la place. Les mises à jour déjà installées ne pourront plus être désinstallées.")
def r_component_cleanup(c):
    rc, out = c.r.run([sys32("dism.exe"), "/Online", "/Cleanup-Image", "/StartComponentCleanup"], timeout=7200,
                      label="DISM /StartComponentCleanup")
    st = parse_dism(out)
    c.add("ok" if st in ("success", "restored") else "warn", "Nettoyage des composants : %s" % st, out.strip()[-600:])


# --------------------------------------------------------------------------- #
#  Synthèse
# --------------------------------------------------------------------------- #

ADVICE = [
    ("RAM", "Garder un seul kit de 2 barrettes identiques, ou désactiver XMP/EXPO, puis utiliser le PC quelques jours. "
            "Confirmer avec MemTest86 (4 passes). Mettre à jour le BIOS peut aussi améliorer la stabilité mémoire."),
    ("Pilote graphique", "Désinstaller proprement le pilote (DDU en mode sans échec) puis installer la dernière version "
                         "stable. Retirer tout overclock GPU."),
    ("Pilote ", "Mettre à jour ce pilote depuis le site du fabricant, ou désinstaller le logiciel associé pour tester."),
    ("Filtre", "Désinstaller temporairement le logiciel qui fournit ce filtre (antivirus, sauvegarde, sync) pour tester."),
    ("Disque", "Sauvegarder les données importantes, vérifier avec CrystalDiskInfo, et envisager le remplacement."),
    ("Alimentation", "Vérifier températures (CPU/GPU), câbles d'alimentation, et l'alimentation elle-même. "
                     "Retirer tout overclock/undervolt."),
    ("Matériel (CPU", "Désactiver PBO / Curve Optimizer / overclock, charger les réglages BIOS par défaut, mettre à jour le BIOS."),
    ("Matériel PCIe", "Retirer/réinsérer la carte concernée, essayer un autre slot, forcer PCIe Gen3 dans le BIOS."),
    ("Fichiers système", "Réparer avec DISM /RestoreHealth puis SFC /scannow (bouton dans les actions recommandées)."),
    ("Système de fichiers", "Corriger le volume avec SpotFix ou une réparation complète au redémarrage."),
    ("Utilitaires", "Désinstaller les utilitaires constructeur inutilisés (RGB, OC, monitoring)."),
    ("Gel", "Analyser les vidages éventuels ; vérifier pilote graphique, températures et RAM."),
]


def build_synthesis(state):
    sus = state.get("suspects") or {}
    if not sus:
        return Finding("ok", "Synthèse", "Synthèse : aucune cause probable de problème détectée",
                       "Les analyses effectuées n'ont rien révélé d'anormal.", key="synthesis")
    items = sorted(sus.items(), key=lambda kv: -kv[1][0])
    top_name, (top_score, _) = items[0]
    lines = ["Classement des causes probables (score = poids des indices) :", ""]
    for name, (score, reasons) in items:
        lines.append("● %s — score %d" % (name, score))
        for r in reasons:
            lines.append("    · " + r)
        adv = next((a for k, a in ADVICE if name.startswith(k) or k in name), None)
        if adv:
            lines.append("    → " + adv)
        lines.append("")
    sev = "crit" if top_score >= 5 else ("warn" if top_score >= 2 else "info")
    return Finding(sev, "Synthèse", "Synthèse : cause la plus probable → %s" % top_name, "\n".join(lines), key="synthesis")


QUICK = ["sysinfo", "crashes", "whea", "ram", "disks", "drivers", "defender"]
FULL = QUICK + ["filters", "sfc_verify", "volume_scan"]


# --------------------------------------------------------------------------- #
#  Interface
# --------------------------------------------------------------------------- #

class App:
    def __init__(self, root):
        self.root = root
        self.ui_q = queue.Queue()
        self.engine = Engine(lambda kind, payload: self.ui_q.put((kind, payload)))
        self.findings = {}
        self.suggestions = {}
        self.log_lines = []
        self._prog_start = None
        self._last_prog = False
        self.admin = is_admin()

        root.title("%s %s" % (APP_NAME, APP_VERSION))
        root.geometry("1280x820")
        root.minsize(980, 640)
        self._style()
        self._build()
        root.after(100, self._poll)
        root.protocol("WM_DELETE_WINDOW", self._close)
        if not IS_WIN:
            self._console("⚠ Ce système n'est pas Windows : les analyses ne fonctionneront pas.", False)

    # ---- style
    def _style(self):
        s = ttk.Style()
        try:
            s.theme_use("vista" if IS_WIN else "clam")
        except tk.TclError:
            s.theme_use("clam")
        s.configure("Treeview", rowheight=24)
        s.configure("Title.TLabel", font=("Segoe UI", 15, "bold"))
        s.configure("Admin.TLabel", foreground="#1b7f3b", font=("Segoe UI", 10, "bold"))
        s.configure("NoAdmin.TLabel", foreground="#b3261e", font=("Segoe UI", 10, "bold"))
        s.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))

    # ---- layout
    def _build(self):
        top = ttk.Frame(self.root, padding=(10, 8))
        top.pack(fill="x")
        ttk.Label(top, text="🩺 " + APP_NAME, style="Title.TLabel").pack(side="left")
        if self.admin:
            ttk.Label(top, text="  ● Administrateur", style="Admin.TLabel").pack(side="left")
        else:
            ttk.Label(top, text="  ● Sans droits admin (analyses limitées)", style="NoAdmin.TLabel").pack(side="left")
            ttk.Button(top, text="Relancer en administrateur", command=self.relaunch_admin).pack(side="left", padx=8)

        bar = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        bar.pack(fill="x")
        ttk.Button(bar, text="▶ Diagnostic rapide (1 min)", style="Accent.TButton",
                   command=lambda: self.start(QUICK)).pack(side="left", padx=(0, 3))
        ttk.Button(bar, text="▶ Diagnostic complet (10-20 min)", style="Accent.TButton",
                   command=lambda: self.start(FULL)).pack(side="left", padx=3)
        self.btn_stop = ttk.Button(bar, text="■ Arrêter", command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=3)
        ttk.Button(bar, text="Exporter le rapport…", command=self.export).pack(side="right", padx=3)
        ttk.Button(bar, text="Copier le rapport", command=self.copy_report).pack(side="right", padx=3)

        mb = ttk.Menubutton(bar, text="Maintenance ▾")
        menu = tk.Menu(mb, tearoff=0)
        for st in STEPS.values():
            if st.menu:
                menu.add_command(label=st.title, command=lambda s=st.sid: self.run_action(s))
        menu.add_separator()
        menu.add_command(label="Analyser un fichier de vidage (.dmp)…", command=self.pick_dump)
        mb["menu"] = menu
        mb.pack(side="left", padx=3)

        main = ttk.PanedWindow(self.root, orient="vertical")
        main.pack(fill="both", expand=True, padx=10, pady=(0, 6))

        upper = ttk.PanedWindow(main, orient="horizontal")
        main.add(upper, weight=5)

        # Étapes
        lf = ttk.LabelFrame(upper, text=" Étapes (double-clic pour relancer) ", padding=4)
        self.steps_tv = ttk.Treeview(lf, columns=("state", "dur"), show="tree headings", height=14)
        self.steps_tv.heading("#0", text="Étape")
        self.steps_tv.heading("state", text="État")
        self.steps_tv.heading("dur", text="Durée")
        self.steps_tv.column("#0", width=265)
        self.steps_tv.column("state", width=90, anchor="center")
        self.steps_tv.column("dur", width=55, anchor="e")
        for st in STEPS.values():
            if st.kind == "analysis":
                self.steps_tv.insert("", "end", iid=st.sid, text=st.title, values=("—", ""))
        self.steps_tv.pack(fill="both", expand=True)
        self.steps_tv.bind("<Double-1>", self._step_dbl)
        for tag, col in (("OK", "#1b7f3b"), ("Attention", "#9a6700"), ("Problème", "#b3261e"),
                         ("En cours", "#0a58ca"), ("Erreur", "#b3261e")):
            self.steps_tv.tag_configure(tag, foreground=col)
        upper.add(lf, weight=1)

        # Constats
        rf = ttk.LabelFrame(upper, text=" Constats ", padding=4)
        rpan = ttk.PanedWindow(rf, orient="vertical")
        rpan.pack(fill="both", expand=True)
        ff = ttk.Frame(rpan)
        self.find_tv = ttk.Treeview(ff, columns=("sev", "cat", "title"), show="headings")
        for col, txt, w in (("sev", "Gravité", 95), ("cat", "Catégorie", 190), ("title", "Constat", 520)):
            self.find_tv.heading(col, text=txt)
            self.find_tv.column(col, width=w, anchor="w")
        sb = ttk.Scrollbar(ff, orient="vertical", command=self.find_tv.yview)
        self.find_tv.configure(yscrollcommand=sb.set)
        self.find_tv.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.find_tv.tag_configure("crit", foreground="#b3261e")
        self.find_tv.tag_configure("warn", foreground="#9a6700")
        self.find_tv.tag_configure("ok", foreground="#1b7f3b")
        self.find_tv.tag_configure("synth", background="#fff4ce", font=("Segoe UI", 10, "bold"))
        self.find_tv.bind("<<TreeviewSelect>>", self._show_detail)
        rpan.add(ff, weight=3)
        self.detail = tk.Text(rpan, height=9, wrap="word", font=("Segoe UI", 10), relief="flat",
                              background="#fafafa", padx=8, pady=6)
        self.detail.configure(state="disabled")
        rpan.add(self.detail, weight=2)
        upper.add(rf, weight=3)

        # Actions recommandées
        af = ttk.LabelFrame(main, text=" Actions recommandées (rien n'est lancé sans votre accord) ", padding=4)
        inner = ttk.Frame(af)
        inner.pack(fill="both", expand=True)
        self.act_tv = ttk.Treeview(inner, columns=("action", "why"), show="headings", height=4)
        self.act_tv.heading("action", text="Action")
        self.act_tv.heading("why", text="Pourquoi")
        self.act_tv.column("action", width=300)
        self.act_tv.column("why", width=700)
        self.act_tv.pack(side="left", fill="both", expand=True)
        self.act_tv.bind("<Double-1>", lambda e: self._run_selected_action())
        ttk.Button(inner, text="Lancer l'action", command=self._run_selected_action).pack(side="left", padx=6)
        main.add(af, weight=1)

        # Console
        cf = ttk.LabelFrame(main, text=" Journal des commandes ", padding=4)
        self.console = tk.Text(cf, height=10, wrap="none", font=("Consolas", 9), background="#1e1e1e",
                               foreground="#d4d4d4", insertbackground="#d4d4d4", relief="flat")
        csb = ttk.Scrollbar(cf, orient="vertical", command=self.console.yview)
        self.console.configure(yscrollcommand=csb.set, state="disabled")
        self.console.tag_configure("cmd", foreground="#4fc1ff")
        self.console.tag_configure("head", foreground="#dcdcaa")
        self.console.tag_configure("err", foreground="#f48771")
        self.console.pack(side="left", fill="both", expand=True)
        csb.pack(side="right", fill="y")
        main.add(cf, weight=2)

        sbar = ttk.Frame(self.root, padding=(10, 0, 10, 6))
        sbar.pack(fill="x")
        self.status = ttk.Label(sbar, text="Prêt.")
        self.status.pack(side="left")
        self.pbar = ttk.Progressbar(sbar, mode="indeterminate", length=200)
        self.pbar.pack(side="right")

    # ---- événements moteur
    def _poll(self):
        try:
            for _ in range(400):
                kind, p = self.ui_q.get_nowait()
                if kind == "console":
                    self._console(*p)
                elif kind == "finding":
                    self._add_finding(p)
                elif kind == "step_status":
                    self._step_status(*p)
                elif kind == "suggest":
                    self._add_suggestion(*p)
                elif kind == "busy":
                    self._busy(p)
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _console(self, text, prog):
        c = self.console
        c.configure(state="normal")
        if prog and self._prog_start is not None:
            c.delete(self._prog_start, "end-1c")
        if prog:
            self._prog_start = c.index("end-1c")
        else:
            self._prog_start = None
        tag = "cmd" if text.startswith("»") else "head" if text.startswith("━━") else \
            "err" if "✖" in text else None
        c.insert("end", text + "\n", tag)
        c.see("end")
        c.configure(state="disabled")
        if prog and self._last_prog and self.log_lines:
            self.log_lines[-1] = text
        else:
            self.log_lines.append(text)
        self._last_prog = prog

    def _add_finding(self, f):
        self.findings[f.id] = f
        vals = (SEV_LABEL[f.sev], f.category, f.title)
        tags = (f.sev, "synth") if f.id == "synthesis" else (f.sev,)
        if self.find_tv.exists(f.id):
            self.find_tv.item(f.id, values=vals, tags=tags)
        else:
            self.find_tv.insert("", 0 if f.id == "synthesis" else "end", iid=f.id, values=vals, tags=tags)
        if f.id == "synthesis":
            self.find_tv.move(f.id, "", 0)
            self.find_tv.selection_set(f.id)
            self.find_tv.see(f.id)
        else:
            self.find_tv.see(f.id)

    def _step_status(self, sid, status, dur):
        if not self.steps_tv.exists(sid):
            self.steps_tv.insert("", "end", iid=sid, text=STEPS[sid].title, values=("—", ""))
        self.steps_tv.item(sid, values=(status, dur), tags=(status,))
        if status == "En cours":
            self.status.configure(text="En cours : %s…" % STEPS[sid].title)

    def _add_suggestion(self, sid, reason):
        if sid in self.suggestions:
            return
        self.suggestions[sid] = reason
        title = "Relancer PC Doctor en administrateur" if sid == "__admin__" else STEPS[sid].title
        self.act_tv.insert("", "end", iid=sid, values=(title, reason))

    def _busy(self, b):
        if b:
            self.pbar.start(12)
            self.btn_stop.configure(state="normal")
        else:
            self.pbar.stop()
            self.btn_stop.configure(state="disabled")
            self.status.configure(text="Terminé — %d constat(s). Voir la synthèse en haut de la liste." % len(self.findings))

    def _show_detail(self, _e=None):
        sel = self.find_tv.selection()
        if not sel:
            return
        f = self.findings.get(sel[0])
        if not f:
            return
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", "%s  —  %s\n\n" % (SEV_LABEL[f.sev], f.title))
        self.detail.insert("end", f.detail or "(pas de détail)")
        self.detail.configure(state="disabled")

    # ---- commandes
    def start(self, steps):
        if self.engine.running:
            if not messagebox.askyesno(APP_NAME, "Une analyse est en cours. Ajouter ces étapes à la file ?"):
                return
        else:
            self.engine.reset()
            for iid in self.find_tv.get_children():
                self.find_tv.delete(iid)
            for iid in self.act_tv.get_children():
                self.act_tv.delete(iid)
            self.findings.clear()
            self.suggestions.clear()
            for iid in self.steps_tv.get_children():
                self.steps_tv.item(iid, values=("—", ""), tags=())
        if not self.admin:
            self._add_suggestion("__admin__", "Vidages, SFC, scan NTFS et filtres nécessitent les droits administrateur")
        for s in steps:
            self.engine.enqueue(s, force=True)

    def _step_dbl(self, _e):
        sel = self.steps_tv.selection()
        if sel:
            self.engine.enqueue(sel[0], force=True)

    def _run_selected_action(self):
        sel = self.act_tv.selection()
        if sel:
            self.run_action(sel[0])

    def run_action(self, sid):
        if sid == "__admin__":
            self.relaunch_admin()
            return
        st = STEPS[sid]
        if st.admin and IS_WIN and not self.admin:
            if messagebox.askyesno(APP_NAME, "« %s » nécessite les droits administrateur.\n\nRelancer PC Doctor "
                                             "en administrateur ?" % st.title):
                self.relaunch_admin()
            return
        if st.confirm and not messagebox.askyesno(APP_NAME, st.confirm):
            return
        if self.act_tv.exists(sid):
            self.act_tv.delete(sid)
            self.suggestions.pop(sid, None)
        self.engine.enqueue(sid, force=True)

    def pick_dump(self):
        p = filedialog.askopenfilename(title="Fichier de vidage", initialdir=os.path.join(SYSROOT, "Minidump"),
                                       filetypes=[("Vidages mémoire", "*.dmp"), ("Tous", "*.*")])
        if p:
            self.engine.state["manual_dump"] = os.path.normpath(p)
            self.engine.enqueue("dump_analysis", force=True)

    def stop(self):
        self.engine.cancel()
        self.status.configure(text="Arrêt demandé…")

    def relaunch_admin(self):
        if not IS_WIN:
            return
        if getattr(sys, "frozen", False):  # version .exe (PyInstaller) : relancer l'exe lui-même
            exe, args = sys.executable, None
        else:
            exe, args = sys.executable, '"%s"' % os.path.abspath(sys.argv[0])
            if exe.lower().endswith("python.exe") and os.path.exists(exe[:-10] + "pythonw.exe"):
                exe = exe[:-10] + "pythonw.exe"
        r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
        if r > 32:
            self._close()

    def report_text(self):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        out = ["%s %s — rapport du %s" % (APP_NAME, APP_VERSION, now),
               "Droits administrateur : %s" % ("oui" if self.admin else "non"), "=" * 78, ""]
        fs = list(self.findings.values())
        fs.sort(key=lambda f: (f.id != "synthesis", -SEV_ORDER[f.sev]))
        for f in fs:
            out.append("[%s] %s — %s" % (SEV_LABEL[f.sev], f.category, f.title))
            if f.detail:
                out.extend("    " + l for l in f.detail.splitlines())
            out.append("")
        if self.suggestions:
            out.append("Actions recommandées :")
            for sid, why in self.suggestions.items():
                out.append("  - %s : %s" % (STEPS[sid].title if sid in STEPS else sid, why))
            out.append("")
        out += ["=" * 78, "Journal des commandes", "=" * 78] + self.log_lines
        return "\n".join(out)

    def copy_report(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.report_text())
        self.status.configure(text="Rapport copié dans le presse-papiers.")

    def export(self):
        name = "PCDoctor_%s.txt" % datetime.datetime.now().strftime("%Y%m%d_%H%M")
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=name,
                                         initialdir=os.path.join(os.path.expanduser("~"), "Desktop"),
                                         filetypes=[("Texte", "*.txt")])
        if p:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(self.report_text())
            self.status.configure(text="Rapport enregistré : %s" % p)

    def _close(self):
        try:
            self.engine.cancel()
        except Exception:
            pass
        self.root.destroy()


def main():
    if tk is None:
        print("Tkinter est requis.")
        sys.exit(1)
    if IS_WIN:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
