# tools/ — 一键工具

## `tee_extract.py` — 主机侧编排工具

把档案里散落的预检 / 采集 / 解析 / 验收脚本串成一条**带门禁**的流水线。

**它不做破坏性操作。** 刷机、写分区、bind mount 一律只打印清单，由人工在可回滚条件下逐条执行。

### 快速开始

```bash
# 0. 拿到档案（本仓库或上游都可以）
git clone https://github.com/balala12345/tee-attestation-extraction
cd tee-attestation-extraction

# 1. 看有哪些机型
python3 tools/tee_extract.py --list

# 2. 只读预检（安全，不碰设备写入路径）
python3 tools/tee_extract.py --check -d nothing2a

# 3. 看完提示，人工执行设备侧提取……

# 4. 拿回产物后做离线验收
python3 tools/tee_extract.py --offline -d xaga --artifacts ./pull/xaga_keybox_extraction_result
```

### 支持机型

| `-d` 值 | 设备 | 目标 |
|---|---|---|
| `nothing2a` | Nothing Phone (2a) / Pacman / MT6886 | Keybox + RKP seed |
| `xaga` | Redmi Note 11T Pro / xaga | Keybox |
| `k70e` | Redmi K70E | RKP/CDI seed（默认只做离线验收） |

### 流程

```
[A] 主机环境检查     adb / python3 / openssl / sha256sum
[B] 设备连接         自动探测或 --serial 指定，多设备时报错退出
[C] 设备门禁         机型 / 槽位 / 内核 / root / TEE 服务 —— 任一不符立即 STOP
[D] 材料完整性       对 99_索引/文件清单_zh-CN.md 做 SHA-256 逐项校验
[E] 离线解析验收     解析并验证_Keybox.py + 描述区 magic/长度/MD5 独立复检
[F] 编译 direct client（可选，--build-client，需 NDK）
[G] 人工步骤清单     只打印，不执行
```

### 关键行为

**门禁是精确匹配，不是子串匹配。**
`ro.product.vendor.device` 必须是 `Pacman`，`PacmanX` / `NotPacman` 都会被拦。

**材料被改动就停。**
对清单里 `04_补丁镜像固件/` 和 `01_教程/` 下的文件逐个校验 SHA-256，任一不符立即 `STOP`（exit 3）。
在真实档案上实测：xaga 229 项、nothing2a 179 项、k70e 38 项，全部通过。

**所有输出落盘。**
每一步的原始 stdout/stderr 写到 `<repo>/_report/`，最后生成 `report_<时间>.md` 和 `.json`。

**退出码**
| 码 | 含义 |
|---|---|
| 0 | 全部阶段通过 |
| 2 | 参数错误 / 找不到档案 |
| 3 | **门禁或材料校验不通过，已中止** |
| 130 | 用户中断 |

### 常用参数

```
--repo PATH        档案根目录（默认从脚本位置/当前目录向上自动查找）
--list             列出机型后退出
-d, --device NAME  目标机型（nothing2a / xaga / k70e）
--serial SN        adb 序列号（不传则自动探测，多设备会报错）
--check            只做只读预检（门禁 + 材料校验）
--offline          纯离线解析，不碰设备（需 --artifacts）
--artifacts DIR    已拉回的产物目录
--build-client     尝试用 NDK 编译 direct client
--yes              跳过交互确认
--version          版本
```

### 为什么做不到"真正的一键"

上游 README 写得很清楚，这里照抄并强调：

- 公开副本**不含**真实输入材料（`device_dump/`、`01_设备输入/`、`03_提取结果/` 都是空的），
  所以**无法从头重建补丁**，只能用 `04_补丁镜像固件/` 里已带的产品；
- 客户端编译需要厂商 TEE 库（`libMcClient.so` / `libTEECommon_64.so`），**未公开**；
- 刷机、绑核、停服务这些破坏性动作**必须人工**在授权设备上做；
- 上游明确声明所有命令「**未逐项人工执行、独立复现或签字确认**」。

所以本工具的定位是**编排 + 门禁 + 验收**，把能自动化的部分自动化，把不能自动化的部分
清清楚楚列出来，而不是假装能一键搞定。

### 依赖

Python 3.8+，无第三方包。外部命令：`adb`、`openssl`、`sha256sum`（或 `shasum`）。
`--build-client` 额外需要 Android NDK（设 `ANDROID_NDK_HOME` 或 `NDK`）。

### 安全边界

- 只执行**只读**的 adb 命令（`getprop` / `uname` / `su -c id` / `get-state`）；
- 不执行 `fastboot` / `dd` / `mount` / `stop`，一行都没有；
- 离线模式完全不接触设备；
- 任何门禁不通过都立刻退出，不"继续往下试试"。

---

## 免责

仅用于**已授权、隔离、可回滚**的实验设备。使用前请确认你的授权状态。
本工具作者不对任何设备损坏、数据丢失或法律后果负责。
