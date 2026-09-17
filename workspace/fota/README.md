# FOTA 服务：间歇联网终端的分批次固件升级

一套可直接运行的参考实现：运营人员上传固件版本后，按**硬件批次 + 阶段（金丝雀→放量）**
逐级灰度；间歇联网终端只领取与自身**型号 / 引导程序版本 / 当前版本**兼容的镜像；
**分块校验续传**；安装失败 A/B 回滚到上一可启动版本并上报原因；批次可暂停/熔断，
且**失败率越阈自动停止扩散**；所有领取与回执幂等，重复上线、重复回执不重复占名额。

## 快速开始（可复现入口）

```bash
# 方式一：容器（推荐，零本地依赖）
docker compose up --build -d
./scripts/demo.sh                 # 容器内驱动 10 台模拟终端走完灰度/断网/熔断
docker compose logs -f fota

# 方式二：容器内跑测试（镜像即测试载体，结果可复现）
docker build -t fota-service:dev .
docker run --rm fota-service:dev test -v

# 方式三：本地 Python
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8080
python -m pytest -q               # 26 项测试
```

- `Dockerfile` 的 `ENTRYPOINT` 是 `entrypoint.sh`：无参数起 API；`test` 跑 pytest；
  其它参数原样执行（demo 用它在同一镜像里跑模拟器）。
- 所有路径、阈值、块大小均由环境变量决定（见下），compose 与测试用同一镜像、同一套默认值。

## 一分钟走查 API

```bash
# 1. 运营上传镜像（multipart：固件 + 型号/版本/引导程序兼容窗口）
curl -F file=@firmware.bin -F model=term-x1 -F version=2.0.0 \
     -F min_bootloader=1.0.0 -F max_bootloader=1.99.0 \
     http://localhost:8080/api/admin/images

# 2. 基于镜像建发布活动，再建按硬件批次的灰度阶段（quota 支持绝对名额/百分比）
curl -X POST localhost:8080/api/admin/campaigns -d '{"name":"q3","image_id":"<img>"}' ...
curl -X POST localhost:8080/api/admin/batches -d '{"campaign_id":"<c>","hardware_batch":"HW2026Q3","stage":1,"quota_mode":"absolute","quota_value":2,"failure_threshold":0.2,"failure_min_sample":5}' ...
curl -X POST localhost:8080/api/admin/batches/<id>/action -d '{"action":"activate"}'
#   动作：activate / pause / halt / resume(熔断后需 force:true) / complete
#   pause、halt 沿 parent_id 向后续阶段级联；activate/resume 只作用本阶段

# 3. 终端侧（每次联网唤醒执行）
curl -X POST localhost:8080/api/device/register -d '{"id":"term-1","model":"term-x1",...}'
curl -X POST localhost:8080/api/device/check-in -H 'X-Device-Id: term-1'
#   offered=true 时返回分块清单（每块 offset/size/sha256）
curl 'localhost:8080/api/device/artifacts/<img>/chunks/0?assignment_id=<a>' -H 'X-Device-Id: term-1'
curl -X POST localhost:8080/api/device/events -H 'X-Device-Id: term-1' \
     -d '{"assignment_id":"<a>","event_type":"installed","idempotency_key":"<每设备每里程碑唯一>","payload":{...}}'
```

交互文档：<http://localhost:8080/docs>

## 设计要点（需求 → 机制）

### 1. 兼容性：型号 / 引导程序 / 当前版本
- 镜像声明 `model`、`min_bootloader`、`max_bootloader`、`version`
  （`app/versioning.py` 做数字/词段混合版本比较）。
- 领用时三重过滤：型号完全相等；引导程序落在闭区间；当前版本 ≠ 目标版本
  （已在目标版本的设备不重复升级）。不匹配的设备在活动激活时也看不到 offer。

### 2. 逐级放量（硬件批次 × 阶段 × 名额）
- `batches` 行 = 某活动面向某 `hardware_batch` 的一个灰度阶段，带 `stage`、
  `quota_mode(absolute|percent)`、`quota_value`、`parent_id`。
- 设备 check-in 时按 `stage` 升序领取**第一个仍有名额的 active 批次**；
  阶段名额互不借用，实现金丝雀→小流量→全量的逐级推进（运营也可显式建后续阶段）。
- 百分比名额按该硬件批次在册设备数实时折算。

### 3. 名额的 exactly-once（重复上线/并发不重占）
两道防线：
1. 服务端进程锁串行化“读计数 → 插 assignment”（`app/rollout.py` 的 `_claim_lock`）；
2. 数据库 UNIQUE(`device_id`,`campaign_id`) 兜底——多 worker/Postgres 下也不可能插入第二条。
  设备再次 check-in 命中既有 assignment，直接返回同一 offer，**永不产生第二个名额**。
- 名额计数包含 installed/failed/in-flight 全部台账行：**失败设备保留名额**，
  抖动重试的设备无法把名额“腾”给别人（有测试 `test_failed_devices_keep_their_seat`）。
- 扩规模建议：把进程锁换成 `SELECT … FOR UPDATE` 行锁 + 切 Postgres（代码注释中标出了位置）。

### 4. 分块、校验、断点续传
- 上传时镜像被切成固定大小块（默认 256 KiB，`CHUNK_SIZE`），每块单独 sha256，
  整块按 `<sha256(block)>.part` 内容寻址存储，附 `manifest.json`（整体 sha256 + 块清单）。
- check-in 返回每块 `{index, offset, size, sha256}`。终端（`client/__init__.py`）：
  - 本地按**块哈希**校验已下载内容，只有哈希不一致/缺失的块才重新请求——
    断电、半截写、旧垃圾都会被识别为重传；
  - 全部块齐后再校验**整包 sha256**，通过才允许进入刷写；
  - 断网随时退出，下次唤醒只拉未验证块（测试覆盖断 1 块、坏块重拉、多次断连）。
  块响应带 `immutable` 缓存头，可被 CDN/边缘缓存安全缓存。

### 5. 安装失败回滚 + 原因上报
- 终端 A/B 双槽：向非活动槽刷写；健康检查失败则把新槽标记 bad、启动旧槽，
  随后发 `failed`（带 `reason` 与 `rolled_back_to`）和 `rollback_complete`。
- 服务端记录 `fail_reason`（可在 `/api/admin/assignments` 查询），
  并把设备影子版本回置为上报的上一可启动版本。
- 设备状态机只允许单向前进：
  `assigned → downloading → downloaded → installing → installed | failed`
  （`app/models.py` 的 `ALLOWED_TRANSITIONS`），乱序/迟到回执返回 409。

### 6. 暂停/熔断的安全语义
以状态机为准，而不是“一刀切断流”（`check_in` / `authorize_chunk` / `record_event` 三处同一规则）：

| 设备所处阶段 | pause / halt 后行为 |
|---|---|
| assigned（尚未开始） | 不再 offer，块接口 409，禁止推进 |
| downloading / downloaded（**未进入安装**） | **不得继续**：check-in 告知 `batch_paused/halted`，块接口 409，`installing` 事件 409 |
| installing（**已写关键区**） | **必须安全收尾**：照常给 manifest/块，允许发 `installed` 或 `failed`+回滚，绝不被半途掐断 |

- `pause` 可恢复（resume）；`halt` 是熔断/急停，**resume 必须显式 `force:true`**。
- 运营 pause/halt 与自动熔断都会**沿阶段树级联**到所有非终态子阶段，停止整条放量路径；
  activate/resume 不级联，后续阶段仍需显式开启。

### 7. 失败率越阈自动停止扩散
- 每次收到终态回执（installed/failed）后重算该批次
  `failure_rate = failed / (installed + failed)`；
  当样本数 ≥ `failure_min_sample` 且失败率 **≥ 批次阈值**（每批次可配，默认 20%）时，
  自动把该批次及全部子阶段置为 halted，并把 halted 批次列表随回执返回，
  设备侧/运营侧立刻可见。
- 判定在同一事务、同一把锁内完成并先 `flush`，保证本次回执计入统计；
  未达最小样本时不误杀（测试覆盖 100% 但样本不足不熔断、阈值边界、级联）。

### 8. 回执幂等（重复回执零副作用）
- 每条回执必须带 `idempotency_key`；`device_events` 对
  UNIQUE(`device_id`,`idempotency_key`) 建唯一索引。
- 重放返回首次结果且 `duplicate:true`：**不迁移状态、不重计失败率、不新增事件行**。
- 终端侧每个里程碑（downloading/installing/installed/failed/…）持久化稳定 key，
  崩溃重启后重放同一 key；若本地状态视图滞后收到 409，会先重新 check-in
  同步权威状态再带新 key 处理，绝不“以为升级了/没升级”。
- `download_started`、`rollback_complete` 是纯遥测事件，不推动状态机，可安全重复。

## 数据模型（`app/models.py`）

```
devices(id, model, hardware_batch, bootloader, current_version, last_seen)
images(id, model, version, min/max_bootloader, size, sha256, chunk_size, chunk_count)
campaigns(id, image_id, name)
batches(id, campaign_id, hardware_batch, stage, quota_mode/value,
        state[pending|active|paused|halted|complete],
        failure_threshold, failure_min_sample, parent_id)
assignments(id, device_id, campaign_id, batch_id,
            install_state, fail_reason, active_slot)   -- UNIQUE(device,campaign)
device_events(id, device_id, assignment_id, event_type, idempotency_key,
              from_state, to_state, payload)           -- UNIQUE(device,idempotency_key)
```

## 验证矩阵

`docker run --rm fota-service:dev test -v` 或本地 `pytest -v`（26 项）：

| 关注点 | 测试文件 |
|---|---|
| 型号/引导窗口/版本过滤、块清单 | `tests/test_compatibility.py` |
| 绝对/百分比名额、阶段顺序、重复 check-in、失败占名额 | `tests/test_rollout_quota.py` |
| 断块续传、坏块重拉、多次断连 | `tests/test_resume.py` |
| 暂停拦截、关键区收尾、级联、force 恢复 | `tests/test_pause_halt.py` |
| 越阈熔断、级联停扩散、阈值边界、原因留档 | `tests/test_failure_halt.py` |
| 回执重放、8 路并发重复上线、名额竞争、乱序拒绝 | `tests/test_idempotency.py` |

真实 HTTP 进程端到端（非 TestClient）也已验证：断 1 块后唤醒只拉剩余块、
暂停中途唤醒返回 `batch_paused`、恢复后续传并安装、2/2 失败自动熔断并级联阶段 3、
失败设备影子版本回滚、安装成功版本跨进程重启保持。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `DATABASE_URL` | 本地 sqlite | SQLAlchemy URL；生产建议 Postgres |
| `STORAGE_ROOT` | `.data/artifacts` | 分块镜像存储目录（compose 挂卷 `/data`） |
| `CHUNK_SIZE` | 262144 | 块大小（字节） |
| `FAILURE_THRESHOLD` / `FAILURE_MIN_SAMPLE` | 0.2 / 3 | 批次默认熔断阈值与最小样本 |
| `SEED_DEMO` | false | 启动时种入一个演示镜像 + 金丝雀批次（compose 开启） |

## 生产化备注（本实现刻意留出的边界）

- 鉴权：管理端应加运营 SSO/角色，设备端用设备证书/签名令牌（当前为裸 header，便于演示）。
- 镜像安全：已做传输与落盘完整性（sha256），上线前应加**发布签名验签**（如 ed25519/minisign），
  终端刷写前校验签名而不仅是哈希。
- 规模：单 worker + 进程锁 + sqlite 用于可复现演示；多实例部署切 Postgres，
  将名额领取改为批次行 `SELECT … FOR UPDATE`，块对象放 S3/CDN（块内容寻址且 immutable，可直接缓存）。
- 回执可加老化归档；`assignments` 建议按 (campaign, device) 分区。
