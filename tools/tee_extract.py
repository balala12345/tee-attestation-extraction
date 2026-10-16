#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TEE 取证一键工具 / TEE Attestation Extraction Toolkit
======================================================

面向 gungnir-sanye/tee-attestation-extraction 档案的**主机侧**编排工具。

  它做什么：设备门禁校验 → 材料完整性校验 → 编译/部署客户端 → 拉取 → 解析 → 密码学验收 → 出报告
  它不做什么：不刷机、不写分区、不改引导链。**所有破坏性步骤都必须你手动执行。**

本工具只编排上游档案里已有的脚本与数据，不重新实现任何提取逻辑。

用法
----
    python3 tee_extract.py --list                       # 看三个机型与各自状态
    python3 tee_extract.py --check --device nothing2a   # 只做只读预检（安全，推荐先跑）
    python3 tee_extract.py --offline --artifacts DIR    # 纯离线：解析已有的原始 bin
    python3 tee_extract.py --device nothing2a           # 交互式全流程（含手动步骤提示）

安全设计
--------
* 默认 dry-run 之外的每一步都要显式确认；`--yes` 才会跳过确认。
* 所有 SHA-256 门禁不通过 → 立即 STOP，绝不继续。
* 每一步的原始输出都落到 `_report/` 下，便于回溯。
* 绝不对设备执行 `dd` / `fastboot flash` / `mount --bind`。

授权提醒
--------
本工具仅用于**已授权、隔离、可回滚**的实验设备。公开档案未包含真实
Keybox/seed/私钥，并且上游明确声明「AI 生成的命令不得直接执行」。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

# ─────────────────────────────── 常量 ───────────────────────────────

VERSION = "1.0.0"
BANNER = f"TEE 取证一键工具 v{VERSION}"

_TTY = sys.stdout.isatty()
C_OK, C_WARN, C_ERR, C_DIM, C_B, C_0 = (
    ("\033[32m", "\033[33m", "\033[31m", "\033[2m", "\033[1m", "\033[0m")
    if _TTY else ("",) * 6
)


def out(msg: str = "") -> None:
    print(msg, flush=True)


def step(n: int | str, title: str) -> None:
    out(f"\n{C_B}━━━ [{n}] {title} ━━━{C_0}")


def ok(msg: str) -> None:
    out(f"  {C_OK}✔{C_0} {msg}")


def warn(msg: str) -> None:
    out(f"  {C_WARN}!{C_0} {msg}")


def err(msg: str) -> None:
    out(f"  {C_ERR}✘{C_0} {msg}")


def info(msg: str) -> None:
    out(f"  {C_DIM}·{C_0} {msg}")


class Stop(Exception):
    """门禁不通过，立即中止（不是 bug，是设计）。"""


# ─────────────────────────────── 机型定义 ───────────────────────────────

@dataclass
class Gate:
    """一条门禁规则。"""
    key: str
    label: str
    expect: Optional[str] = None      # 期望的精确值
    match: Optional[str] = None       # 或正则
    prop: Optional[str] = None        # 用 getprop 读
    command: Optional[str] = None     # 或执行任意 shell
    hint: str = ""


@dataclass
class Device:
    slug: str
    name: str
    dirname: str
    gates: list[Gate] = field(default_factory=list)
    # 档案内可复用的脚本 / 二进制（相对 dirname）
    scripts: dict[str, str] = field(default_factory=dict)
    notes: str = ""


DEVICES: dict[str, Device] = {
    "nothing2a": Device(
        slug="nothing2a",
        name="Nothing Phone (2a) / Pacman / MT6886 — Keybox + RKP seed",
        dirname="01_Nothing2A_RKP种子_Keybox",
        gates=[
            Gate("device", "ro.product.vendor.device", expect="Pacman", prop="ro.product.vendor.device"),
            Gate("model", "ro.product.model", expect="A142", prop="ro.product.model"),
            Gate("slot", "ro.boot.slot_suffix", expect="_a", prop="ro.boot.slot_suffix",
                 hint="本篇教程要求 A 槽；B 槽请先切回"),
            Gate("root", "su 可用", match=r"uid=0\(", command="su -c id",
                 hint="拿不到 root，后续 persist 读取会失败"),
            Gate("tee", "tee-1-1 已运行", expect="running", prop="init.svc.tee-1-1",
                 hint="tee 未运行说明 patched TEE 没生效，禁止继续"),
        ],
        scripts={
            "precheck": "04_补丁镜像固件/01_patch/source_full/00_设备预检_Nothing2A.sh",
            "keybox_run": "04_补丁镜像固件/01_patch/source_full/01_运行_Keybox_采集.sh",
            "rkp_run": "04_补丁镜像固件/01_patch/source_full/03_提取_RKP_CDI_seed.sh",
            "rkp_verify": "04_补丁镜像固件/01_patch/source_full/04_验收_RKP_CDI_seed.sh",
            "parse_keybox": "04_补丁镜像固件/01_patch/source_full/解析_Keybox_包内.py",
            "extract_seed": "04_补丁镜像固件/01_patch/source_full/提取_rkp_bcc_km_seed.py",
            "client_src": "04_补丁镜像固件/01_patch/source_full/keymint_tee_client/kmtee_probe.c",
            "client_dir": "04_补丁镜像固件/01_patch/source_full/keymint_tee_client",
            "patch_ta": "04_补丁镜像固件/01_patch/patched_binaries/0706000000000000000000000000004d.dumpkeybox.tlbin",
        },
        notes="Keybox 走 mcOpenTrustlet 直载 patched TA；RKP seed 走 rkp_bcc_kdf_keygenleak。",
    ),
    "xaga": Device(
        slug="xaga",
        name="Redmi Note 11T Pro / xaga — Keybox",
        dirname="02_Redmi11TPro_Keybox",
        gates=[
            Gate("device", "ro.product.vendor.device", expect="xaga", prop="ro.product.vendor.device"),
            Gate("slot", "ro.boot.slot_suffix", expect="_b", prop="ro.boot.slot_suffix",
                 hint="本方案只改 B 槽，A 槽必须保持原厂"),
            Gate("kernel", "uname -r",
                 expect="5.10.66-android12-9-00001-g41ff3fa8fff9-ab8171928",
                 command="uname -r", hint="内核不匹配 = 精确补丁不适用，必停"),
            Gate("root", "su 可用", match=r"uid=0\(", command="su -c id",
                 hint="拿不到 root，后续 persist 读取会失败"),
        ],
        scripts={
            "build_patch": "04_补丁镜像固件/01_patch/source_full/构建_Keybox只读提取补丁.py",
            "device_collect": "04_补丁镜像固件/01_patch/source_full/设备端_Keybox只读采集.sh",
            "deploy": "04_补丁镜像固件/01_patch/source_full/设备端_部署_Keybox只读引导链.sh",
            "extract": "04_补丁镜像固件/01_patch/source_full/设备端_覆盖TA并提取Keybox.sh",
            "rollback": "04_补丁镜像固件/01_patch/source_full/设备端_回滚_Keybox引导链.sh",
            "verify": "04_补丁镜像固件/01_patch/source_full/解析并验证_Keybox.py",
            "client": "04_补丁镜像固件/01_patch/source_full/Keybox读取客户端/xaga_keybox_readonly.c",
            "client_dir": "04_补丁镜像固件/01_patch/source_full/Keybox读取客户端",
            "patched_ta": "04_补丁镜像固件/01_patch/keybox_readonly_patch/d91f322ad5a441d5955110eda3272fc0_caller_gate_nop.ta",
        },
        notes="只读命令 0x64；不放开写命令 0/0x65/0x66。",
    ),
    "k70e": Device(
        slug="k70e",
        name="Redmi K70E — RKP/CDI seed + Google 签发",
        dirname="03_RedmiK70E_RKP种子",
        gates=[
            Gate("device", "机型", match=r"(?i)(k70e|duchamp)", command="getprop ro.product.vendor.device",
                 hint="K70E 跨设备移植需 profile 生成器，非字节级匹配会 fail-closed"),
            Gate("root", "su 可用", match=r"uid=0\(", command="su -c id",
                 hint="拿不到 root，后续 persist 读取会失败"),
        ],
        scripts={
            "verify_submission": "04_补丁镜像固件/01_patch/diagnostic_scripts/run_google_rkp_sw_vanilla_cdi_default_once.py",
            "capture_seed": "04_补丁镜像固件/01_patch/diagnostic_scripts/capture_device_bcc_seed_once.py",
            "extract_leaf": "04_补丁镜像固件/01_patch/diagnostic_scripts/extract_device_cdi_leaf_from_mitee_log.py",
            "audit_frames": "04_补丁镜像固件/01_patch/diagnostic_scripts/audit_device_keymint_begin_frames_hostonly.py",
        },
        notes=(
            "⚠ K70E 的 patched-TA/TEE 路线已被上游标记『禁止重跑』（旧证书含 NOT_APPROVED）。\n"
            "    现行路线 = stock MiTEE 日志（教程文档 54）。默认只做离线验收。"
        ),
    ),
}


# ─────────────────────────────── 工具函数 ───────────────────────────────

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def which(*names: str) -> Optional[str]:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def run(cmd: list[str] | str, *, timeout: int = 120, check: bool = False,
        shell: bool = False) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, timeout=timeout, shell=shell, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        so = r.stdout.decode(errors="replace")
        se = r.stderr.decode(errors="replace")
        if check and r.returncode != 0:
            raise Stop(f"命令失败 ({r.returncode}): {cmd}\n{se[:500]}")
        return r.returncode, so, se
    except subprocess.TimeoutExpired:
        return 124, "", f"超时 {timeout}s"
    except FileNotFoundError as e:
        return 127, "", str(e)


def adb(serial: str, *args: str, **kw) -> tuple[int, str, str]:
    base = ["adb"]
    if serial:
        base += ["-s", serial]
    return run(base + list(args), **kw)


def confirm(prompt: str, *, assume_yes: bool) -> bool:
    if assume_yes:
        out(f"  {C_DIM}--yes 已启用，自动确认：{prompt}{C_0}")
        return True
    try:
        ans = input(f"  {C_WARN}?{C_0} {prompt} [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        out("")
        return False
    return ans in ("y", "yes", "是")


class Report:
    """收集每步结果，最后落盘 JSON + Markdown。"""

    def __init__(self, root: Path):
        self.root = root / "_report"
        self.root.mkdir(parents=True, exist_ok=True)
        self.entries: list[dict] = []
        self.session = time.strftime("%Y%m%d_%H%M%S")

    def add(self, phase: str, name: str, status: str, detail: str = "",
            output: str = "") -> None:
        self.entries.append({
            "phase": phase, "name": name, "status": status,
            "detail": detail, "ts": time.time(),
        })
        icon = {"pass": ok, "warn": warn, "fail": err, "skip": info}.get(status, info)
        icon(f"{name}" + (f" — {detail}" if detail else ""))
        if output:
            safe = re.sub(r"[^\w.\-]+", "_", f"{phase}_{name}")[:80]
            (self.root / f"{safe}.log").write_text(output, encoding="utf-8")

    def finish(self) -> None:
        (self.root / f"report_{self.session}.json").write_text(
            json.dumps({"version": VERSION, "session": self.session,
                        "entries": self.entries}, ensure_ascii=False, indent=2),
            encoding="utf-8")

        counts: dict[str, int] = {}
        for e in self.entries:
            counts[e["status"]] = counts.get(e["status"], 0) + 1

        md = [f"# TEE 取证报告 — {self.session}", "",
              f"工具版本：`{VERSION}`  ", f"报告目录：`{self.root}`", "",
              "## 汇总", ""]
        for k, label in (("pass", "通过"), ("warn", "警告"), ("fail", "失败"), ("skip", "跳过")):
            if counts.get(k):
                md.append(f"- {label}：**{counts[k]}**")
        md += ["", "## 明细", "", "| 阶段 | 项目 | 状态 | 说明 |", "|---|---|---|---|"]
        for e in self.entries:
            d = e["detail"].replace("|", "\\|")
            md.append(f"| {e['phase']} | {e['name']} | {e['status']} | {d} |")
        md += ["", "---", "",
               "> 本报告由自动工具生成，**不构成人工验收结论**。",
               "> 任何 `pass` 仅表示该条自动检查通过，不代表整个提取流程已被独立复现。"]

        (self.root / f"report_{self.session}.md").write_text("\n".join(md), encoding="utf-8")
        out("")
        out(f"  {C_B}报告已生成：{C_0}")
        out(f"    {self.root / f'report_{self.session}.md'}")
        out(f"    {self.root / f'report_{self.session}.json'}")


# ─────────────────────────────── 阶段实现 ───────────────────────────────

def stage_preflight_host(rp: Report) -> dict[str, str]:
    """主机环境检查。返回可用工具字典。"""
    step("A", "主机环境检查")
    tools = {}
    for name, alt, need in (("adb", (), True), ("python3", ("python",), True),
                            ("openssl", (), True), ("sha256sum", ("shasum",), False)):
        p = which(name, *alt)
        if p:
            tools[name] = p
            ok(f"{name}: {p}")
        elif need:
            err(f"{name}: 未找到（必需）")
        else:
            warn(f"{name}: 未找到（可选）")
    if not tools.get("adb"):
        raise Stop("缺少 adb，无法继续设备相关流程")
    return tools


def stage_pick_device(rp: Report, serial: str, dev: Device) -> None:
    step("B", f"连接设备 — {dev.name}")
    if not serial:
        rc, so, se = run(["adb", "devices", "-l"])
        out(textwrap.indent(so.rstrip(), "    "))
        lines = [l for l in so.splitlines()[1:] if l.strip() and "\tdevice" in l]
        if not lines:
            raise Stop("adb 未发现任何 device 状态设备")
        if len(lines) > 1:
            raise Stop(f"发现 {len(lines)} 台设备，请用 --serial 明确指定")
        serial = lines[0].split()[0]
    rc, so, _ = adb(serial, "get-state")
    if "device" not in so:
        raise Stop(f"{serial} 状态不是 device：{so.strip()}")
    ok(f"serial={serial} 在线")
    rp.add("B", "adb 连接", "pass", f"serial={serial}")


def _match_gate(g: Gate, val: str) -> bool:
    """门禁比对。

    expect 为精确匹配（去首尾空白后全等），match 为正则搜索。
    早期版本用 `in` 做子串匹配，会让 'NotPacman' 这类错误值意外通过 —— 已修正。
    """
    v = val.strip()
    if g.expect is not None:
        return v == g.expect
    if g.match is not None:
        return re.search(g.match, v) is not None
    return False


def stage_gates(rp: Report, serial: str, dev: Device) -> None:
    step("C", f"设备门禁（{len(dev.gates)} 项，任一不符立即 STOP）")
    for g in dev.gates:
        if g.command:
            # su 需要 `adb shell su -c '<cmd>'` —— -c 的实参必须作为独立 argv 传递
            parts = g.command.split(None, 1)
            if parts[0] == "su":
                sub = parts[1][3:].strip() if len(parts) > 1 and parts[1].startswith("-c ") else "id"
                rc, so, _ = adb(serial, "shell", "su", "-c", sub)
            else:
                # 普通命令按空白拆分成 argv，避免 `adb shell "uname -r"` 被当成单参数
                rc, so, _ = adb(serial, "shell", *g.command.split())
        elif g.prop:
            rc, so, _ = adb(serial, "shell", "getprop", g.prop)
        else:
            continue
        val = so.strip().replace("\r", "")
        passed = _match_gate(g, val)
        status = "pass" if passed else "fail"
        rp.add("C", f"{g.label}", status, f"{val!r}", output=so)
        if not passed:
            want = g.expect if g.expect is not None else g.match
            msg = f"门禁不符：{g.label} 期望 {want!r}，实际 {val!r}"
            if g.hint:
                msg += f"\n      提示：{g.hint}"
            raise Stop(msg)
    ok(f"全部 {len(dev.gates)} 项门禁通过")


def stage_materials(rp: Report, dev: Device, repo: Path) -> None:
    step("D", "档案材料完整性（SHA-256）")
    ddir = repo / dev.dirname
    if not ddir.is_dir():
        raise Stop(f"找不到机型目录：{ddir}")

    manifest = ddir / "99_索引" / "文件清单_zh-CN.md"
    if not manifest.is_file():
        warn("未找到 SHA-256 清单，跳过（不代表材料没问题）")
        rp.add("D", "清单存在性", "warn", "缺少 99_索引/文件清单_zh-CN.md")
        return

    text = manifest.read_text(encoding="utf-8", errors="replace")
    pairs = re.findall(r"^([0-9a-fA-F]{64})\s{2,}(.+?)$", text, re.M)
    if not pairs:
        warn("清单里没解析到 SHA-256 条目")
        rp.add("D", "清单解析", "warn", "0 条目")
        return
    info(f"清单共 {len(pairs)} 条")

    # 只校验清单里列出的、且在 04_补丁镜像固件 / 关键脚本下的文件，避免全量扫描拖时间
    checked = bad = missing = 0
    for digest, rel in pairs:
        rel = rel.strip()
        if not rel.startswith(("04_补丁镜像固件", "01_教程")):
            continue
        f = ddir / rel
        if not f.is_file():
            missing += 1
            continue
        checked += 1
        if sha256_file(f) != digest.lower():
            bad += 1
            err(f"哈希不符：{rel}")
    if bad:
        rp.add("D", "SHA-256 校验", "fail", f"{bad} 个不符 / 已校验 {checked}")
        raise Stop("材料哈希不符 —— 材料可能被改动或版本不对，禁止继续")
    rp.add("D", "SHA-256 校验", "pass",
           f"已校验 {checked}，缺失 {missing}（缺失多为去敏后未公开的输入材料）")
    if missing:
        warn(f"{missing} 个清单条目在公开副本中不存在（教程引用的输入材料未公开）")
        warn("这意味着**无法从头重建补丁**，只能使用 04_补丁镜像固件 里已带的产品")


def stage_offline_verify(rp: Report, dev: Device, repo: Path,
                        artifacts: Path, assume_yes: bool) -> None:
    step("E", "离线解析与密码学验收")
    ddir = repo / dev.dirname

    if dev.slug == "xaga":
        payload = artifacts / "keybox_原始载荷.bin"
        desc = artifacts / "keybox_描述区.bin"
        if not payload.is_file():
            # 也接受 tar 解出来的目录结构
            for c in artifacts.rglob("keybox_原始载荷.bin"):
                payload = c
                desc = c.parent / "keybox_描述区.bin"
                break
        if not payload.is_file() or not desc.is_file():
            raise Stop(f"未找到 keybox_原始载荷.bin / keybox_描述区.bin（在 {artifacts}）")
        info(f"载荷 {payload} ({payload.stat().st_size} B)")
        info(f"描述区 {desc} ({desc.stat().st_size} B)")

        outdir = artifacts / "解析验证结果"
        script = ddir / dev.scripts["verify"]
        rc, so, se = run([sys.executable, str(script), str(payload), str(desc), str(outdir)],
                         timeout=300)
        out(textwrap.indent(so.rstrip() or se.rstrip(), "    "))
        status = "pass" if rc == 0 else "fail"
        rp.add("E", "解析并验证_Keybox.py", status, f"rc={rc}", output=so + se)
        if status == "fail":
            raise Stop("Keybox 解析/验证未通过")
        # 二次独立验收：描述区 magic / 长度 / MD5
        _xaga_extra_checks(rp, desc, payload)

    elif dev.slug == "nothing2a":
        after = None
        for c in artifacts.rglob("attest_keybox_buf_after.bin"):
            after = c
            break
        if after is None:
            raise Stop(f"未找到 attest_keybox_buf_after.bin（在 {artifacts}）")
        info(f"buffer-after {after} ({after.stat().st_size} B)")
        head = after.read_bytes()[:16]
        info("前缀: " + " ".join(f"{b:02x}" for b in head))
        expect_pfx = bytes.fromhex("01000000")
        st = "pass" if head.startswith(expect_pfx) else "warn"
        rp.add("E", "明文前缀检查", st,
               "01 00 00 00 … 符合 keybox 明文结构" if st == "pass"
               else f"前缀异常 {head[:4].hex()}（stock TA 不回写明文是预期行为）")
        info("完整拆分请运行：python3 解析_Keybox_包内.py <buf_after.bin> <outdir>")

    else:  # k70e
        info("K70E 默认路线为离线验收，请使用上游 verify_submission.py：")
        info("  cd <提交包> && python3 <skill>/scripts/verify_submission.py \"$PWD\"")
        info("  预期：exit 非 0 且 status=FAIL，仅 Provisioning Info 门失败（旧包已知）")
        rp.add("E", "K70E 离线验收", "skip", "需手动运行上游 verify_submission.py")


def _xaga_extra_checks(rp: Report, desc: Path, payload: Path) -> None:
    """与上游 解析并验证_Keybox.py 相同语义的独立复检。

    描述区 = 38 × uint32 LE；结构（对齐上游实现）：
      word[0]  magic         = 0x12345678
      word[1]  未知
      word[2]  payload 长度   = len(payload)
      word[3:8] 保留，必须为 0
      末 16B    = md5(payload)
    """
    import struct

    d = desc.read_bytes()
    if len(d) != 168:
        rp.add("E", "描述区长度", "fail", f"{len(d)} B != 168 B")
        return
    words = list(struct.unpack_from("<38I", d, 0))

    rp.add("E", "描述区 magic",
           "pass" if words[0] == 0x12345678 else "fail",
           f"0x{words[0]:08x}" + ("" if words[0] == 0x12345678 else " != 0x12345678"))

    plen = payload.stat().st_size
    rp.add("E", "描述区 payload 长度",
           "pass" if words[2] == plen else "fail",
           f"descriptor={words[2]} payload={plen}")

    rp.add("E", "保留字清零",
           "pass" if not any(words[3:8]) else "fail",
           f"word[3:8]={[hex(w) for w in words[3:8]]}")

    md5_ok = d[-16:] == hashlib.md5(payload.read_bytes()).digest()
    rp.add("E", "描述区 MD5 == 载荷 MD5", "pass" if md5_ok else "fail",
           f"descriptor_md5={d[-16:].hex()}")

    if not (words[0] == 0x12345678 and words[2] == plen and md5_ok):
        raise Stop("Keybox 描述区自检未通过（magic/长度/MD5 至少一项不符）")


def stage_build_client(rp: Report, dev: Device, repo: Path, assume_yes: bool) -> Optional[Path]:
    """尝试编译 direct client（需要 NDK）。失败不致命。"""
    step("F", "编译 direct client（可选）")
    ndk = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("NDK")
    if not ndk:
        for guess in (Path.home() / "Android/Sdk/ndk", Path("/opt/android-ndk")):
            if guess.is_dir():
                subs = sorted([p for p in guess.iterdir() if p.is_dir()])
                if subs:
                    ndk = str(subs[-1])
                    break
    if not ndk:
        warn("未找到 Android NDK（设 ANDROID_NDK_HOME 或 NDK）。跳过编译。")
        rp.add("F", "NDK 检测", "skip", "未设置 ANDROID_NDK_HOME/NDK")
        return None

    ddir = repo / dev.dirname
    info(f"NDK = {ndk}")
    clang = None
    for c in Path(ndk).rglob("aarch64-linux-android*-clang"):
        clang = c
        break
    if not clang:
        warn("NDK 里没找到 aarch64-linux-android*-clang")
        rp.add("F", "clang 查找", "skip", "未找到 aarch64 clang")
        return None

    if dev.slug == "nothing2a":
        src = ddir / dev.scripts["client_src"]
        outdir = ddir / dev.scripts["client_dir"]
        exe = outdir / "kmtee_probe"
        cmd = [str(clang), "-Wall", "-O2", str(src), "-o", str(exe),
               "-Ldevice_dump/vendor_lib64", "-lMcClient",
               "-Wl,-rpath,/vendor/lib64"]
        rc, so, se = run(cmd, timeout=600)
        if rc != 0:
            warn("编译失败（通常因为缺 device_dump/vendor_lib64/libMcClient.so —— 该库未公开）")
            rp.add("F", "编译 kmtee_probe", "warn", f"rc={rc}", output=so + se)
            return None
        ok(f"已产出 {exe}")
        rp.add("F", "编译 kmtee_probe", "pass", str(exe))
        return exe
    else:
        warn("xaga/K70E 的客户端编译需厂商 TEE 库（未公开），本工具不代编译")
        rp.add("F", "客户端编译", "skip", "需要未公开的厂商库")
        return None


def stage_manual_plan(rp: Report, dev: Device, repo: Path) -> None:
    """打印必须人工执行的破坏性步骤清单。"""
    step("G", "人工步骤清单（本工具不会代做任何破坏性操作）")
    ddir = repo / dev.dirname

    if dev.slug == "nothing2a":
        rows = [
            ("刷 patched LK", "fastboot flash lk_a pacman-fenrir-minimal.bin",
             "放开启动链校验 —— 会让 verified boot 变为 orange"),
            ("刷 patched TEE", "fastboot flash tee_a tee-patched-slot_a.img",
             "放开 TA 签名校验；务必用 A-only 版本，不要用 tee_patched.img"),
            ("刷 root 镜像", "fastboot flash init_boot_a root_boot_patched.img",
             "Magisk root，用于读 persist 与跑 native client"),
            ("重启进研究环境", "adb reboot", "重启后必须重跑本工具的 --check"),
        ]
        img_dir = ddir / "04_补丁镜像固件" / "02_images"
        info(f"镜像目录：{img_dir}")
        for f in sorted(img_dir.glob("*.img")):
            info(f"  {f.name}  ({f.stat().st_size:,} B)")
        info("⚠ 缺 pacman-fenrir-minimal.bin（未公开），需要授权工作区里的原件")

    elif dev.slug == "xaga":
        rows = [
            ("部署 B 槽补丁", f"sh {dev.scripts['deploy']}",
             "脚本自带序列号/内核/槽位/哈希门禁，仅写 lk_b 与 tee_b"),
            ("重启", "adb reboot", "重启后确认补丁 TEE 已生效"),
            ("提取", f"sh {dev.scripts['extract']}",
             "停止 keymint-beanpod，bind mount patched TA，只调用只读命令 0x64"),
            ("回滚", f"sh {dev.scripts['rollback']}",
             "用写前完整备份回写，回滚后必须完整 SHA-256 回读"),
        ]
        warn("执行前必须：使用 设备端_实机LK只读备份.sh 做写前完整备份")
    else:
        rows = [
            ("⚠ 禁止", "patched TA/TEE 路线", "上游已标记 NOT_APPROVED，禁止重跑"),
            ("现行路线", "stock MiTEE 日志（教程文档 54）", "只读捕获，不刷机"),
            ("离线验收", "verify_submission.py", "预期 FAIL 在 Provisioning Info 门"),
        ]

    for name, cmd, why in rows:
        out(f"    {C_B}{name}{C_0}")
        out(f"      $ {cmd}")
        out(f"      {C_DIM}{why}{C_0}")
    rp.add("G", "人工步骤清单", "skip", f"{len(rows)} 条，需人工执行")


def stage_list(repo: Path) -> None:
    out(f"\n{C_B}{BANNER}{C_0}")
    out(f"档案根目录：{repo}\n")
    for slug, d in DEVICES.items():
        ddir = repo / d.dirname
        exists = "✔" if ddir.is_dir() else "✘"
        out(f"  {exists} {C_B}{slug:<10}{C_0} {d.name}")
        out(f"      {C_DIM}{d.dirname}{C_0}")
        if d.notes:
            out(f"      {C_DIM}{d.notes}{C_0}")
        info(f"  门禁 {len(d.gates)} 项；脚本 {len(d.scripts)} 个")
        out("")


# ─────────────────────────────── 主流程 ───────────────────────────────

def find_repo(explicit: Optional[str]) -> Path:
    """定位档案根目录（含 01_/02_/03_ 三个机型目录）。"""
    cands: list[Path] = []
    if explicit:
        cands.append(Path(explicit).expanduser().resolve())
    here = Path(__file__).resolve().parent
    cands += [here, *here.parents]
    cands += [Path.cwd(), *Path.cwd().parents]
    for c in cands:
        try:
            if (c / "01_Nothing2A_RKP种子_Keybox").is_dir() and (c / "README.md").is_file():
                return c
        except OSError:
            continue
    raise Stop(
        "找不到档案根目录（需包含 01_Nothing2A_RKP种子_Keybox/ 与 README.md）。\n"
        "      请用 --repo <路径> 指定，例如：\n"
        "        git clone https://github.com/balala12345/tee-attestation-extraction\n"
        "        python3 tee_extract.py --repo ./tee-attestation-extraction --list"
    )


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="tee_extract.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=BANNER,
        epilog=textwrap.dedent("""
            示例
              python3 tee_extract.py --list
              python3 tee_extract.py --repo ./tee-attestation-extraction --check -d nothing2a
              python3 tee_extract.py --offline -d xaga --artifacts ./pull/xaga_keybox_extraction_result

            安全说明
              本工具永不执行 fastboot flash / dd / mount。破坏性步骤只打印清单，由人工执行。
              任何 SHA-256 门禁不通过都会立即中止（exit 3）。
                """),
    )
    ap.add_argument("--repo", help="档案根目录（默认自动查找）")
    ap.add_argument("--list", action="store_true", help="列出支持的机型后退出")
    ap.add_argument("-d", "--device", choices=sorted(DEVICES), help="目标机型")
    ap.add_argument("--serial", default="", help="adb 序列号（不传则自动探测）")
    ap.add_argument("--check", action="store_true", help="只做只读预检（门禁+材料校验），安全")
    ap.add_argument("--offline", action="store_true", help="纯离线：只解析已有产物，不碰设备")
    ap.add_argument("--artifacts", type=Path, help="离线模式：已拉回的产物目录")
    ap.add_argument("--build-client", action="store_true", help="尝试用 NDK 编译 direct client")
    ap.add_argument("--yes", action="store_true", help="跳过所有交互确认")
    ap.add_argument("--version", action="version", version=BANNER)
    args = ap.parse_args(argv)

    try:
        repo = find_repo(args.repo)
    except Stop as e:
        err(str(e))
        return 2

    if args.list:
        stage_list(repo)
        return 0

    if not args.device and not args.offline:
        err("请用 -d/--device 指定机型，或加 --list 查看可用机型")
        return 2

    dev = DEVICES[args.device] if args.device else None
    if args.offline and dev is None:
        err("--offline 也需要 -d/--device（决定用哪个解析器）")
        return 2

    rp = Report(repo)
    out(f"\n{C_B}{BANNER}{C_0}")
    out(f"  档案：{repo}")
    out(f"  机型：{dev.name}")
    out(f"  模式：{'只读预检' if args.check else ('离线解析' if args.offline else '完整流程')}")
    if dev.notes:
        out(f"  {C_WARN}注意：{C_0}{dev.notes}")

    try:
        if args.offline:
            if not args.artifacts:
                err("--offline 需要 --artifacts <目录>")
                return 2
            stage_offline_verify(rp, dev, repo, args.artifacts, args.yes)
        else:
            stage_preflight_host(rp)
            stage_pick_device(rp, args.serial, dev)
            stage_gates(rp, args.serial, dev)
            stage_materials(rp, dev, repo)
            if args.build_client:
                stage_build_client(rp, dev, repo, args.yes)
            if args.check:
                ok("只读预检完成（未触碰设备写入路径）")
            else:
                stage_manual_plan(rp, dev, repo)
                out("")
                warn("本工具到此为止。上面的破坏性步骤请人工、逐条、在可回滚条件下执行。")
                warn("执行完设备侧提取后，用 --offline --artifacts <目录> 回来做验收。")
    except Stop as e:
        rp.add("!", "流程中止", "fail", str(e).split("\n")[0])
        rp.finish()
        out("")
        err(f"STOP：{e}")
        return 3
    except KeyboardInterrupt:
        out("")
        err("用户中断")
        rp.finish()
        return 130

    rp.finish()
    return 0


if __name__ == "__main__":
    sys.exit(main())
