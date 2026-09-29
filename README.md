# 核技术应用许可与流转平台

本项目是一套可离线运行的 Python 服务端平台，用于管理数据中心、互联通道、加速卡资源批次、租户预约、容量分配、交付情景与硬件稳定性准入，并提供核技术应用许可与产品批次流转的授权链追踪。业务状态、幂等结果和审计事件保存在 SQLite 中，适合调度、质量、风险和审计人员在单个 Linux 应用容器内协作。

## 目录

- `src/compute_fabric/`：站点、通道、资源库存、预约、容量分配和情景分析；
- `src/accelerator_lab/`：加速卡测点导入、排除复核、分析任务租约和准入决定；
- `src/silicon_qualification/`：AI 加速芯片批次、测量、分析与质量审批；
- `src/nuclear_licensing/`：核技术应用许可范围、持有人、场所资质、产品批次交接与双时间轴合规审查；
- `fixtures/`：离线验收使用的结构化协议与测点（含 `licensing_demo.json` 授权链剧本）；
- `tests/`：核心规则、错误边界、事务、API 和命令行验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m compute_fabric.acceptance --workspace .
PYTHONPATH=src python3 -m accelerator_lab.acceptance --workspace .
PYTHONPATH=src python3 -m silicon_qualification.acceptance
PYTHONPATH=src python3 -m nuclear_licensing.acceptance --workspace .
```

这些命令使用临时 SQLite 数据库完成站点、资源、预约、分配、测点分析、芯片准入以及许可登记、批次交接、撤销阻断与历史重建流程，不访问外部网络。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m compute_fabric.api --database compute.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m accelerator_lab.api --database lab.sqlite3 --host 127.0.0.1 --port 8081
PYTHONPATH=src python3 -m silicon_qualification.api --database silicon.sqlite3 --host 127.0.0.1 --port 8082
PYTHONPATH=src python3 -m nuclear_licensing.api --database licensing.sqlite3 --host 127.0.0.1 --port 8083
```

服务均提供 `GET /health`，其余接口使用 JSON。进程重启后可以继续查询 SQLite 中的业务状态和审计历史。

## 许可与流转授权链（nuclear_licensing）

许可批文、场所资质、交接单各自只反映局部事实，授权链服务把它们按双时间轴连成可追溯整体：

- **业务时间轴**：许可有效期、场所资质区间、交接实际发生时刻（`occurred_at`）；
- **登记时间轴**：凭证进入系统的时刻（`recorded_at`）。交接单和增补范围允许补录，
  登记时刻可以晚于业务时刻，但事实行只追加、不覆盖。

由此得到的关键语义：

1. **许可撤销独立成事实**。撤销在生效时点之后硬性阻断后续运输/使用/转让登记，
   但撤销时点之前已合法完成的交接保持 `authorized`，历史不被抹去。
2. **合规审查结案即冻结知识截止时点**。结案后补录的迟到凭证（补录的许可范围、
   追溯撤销、迟到交接单）不会改写冻结结论，而是在 `late_evidence` 中逐条列出；
   `current_view` 仅作对照展示。要采用新证据须显式 `reopen` 后重新结案。
3. **审计查询给出具体依据与缺口**。每个结论返回逐条 finding：许可批文号、范围
   凭证、场所资质、撤销/停用事实，或 `missing`/`blocked` 的具体环节；链断裂时
   持有人停在断点，指出“应由谁交出”。
4. **历史时点重建**：`GET /batches/{id}/chain?as_of=...&knowledge_cutoff=...`
   可还原“在那一天、以当时已知凭证”看到的授权状态。

角色：`registry`（登记单位/场所/许可/批次）、`dispatcher`（登记交接单）、
`compliance`（合规审查）、`auditor`（查询授权链与审计哈希链）。

主要接口（均需 `X-Actor-Id` 头）：

| 方法/路径 | 说明 |
| --- | --- |
| `POST /orgs`、`POST /sites`、`POST /sites/{id}/suspensions` | 单位、场所与停用登记 |
| `POST /licenses`、`POST /licenses/{id}/scopes`、`POST /licenses/{id}/revoke` | 许可批文、范围（含 `backfilled` 补录标记）与撤销 |
| `POST /batches` | 产品批次登记 |
| `POST /handoffs` | 交接单登记（幂等键；硬阻断返回 409 及 findings，缺凭证登记为 incomplete） |
| `GET /batches/{id}/chain` | 授权链重建，支持 `as_of`、`knowledge_cutoff` |
| `POST /batches/{id}/authorize` | 某批次在某日能否由指定单位 transport/use/transfer |
| `POST /reviews`、`POST /reviews/{id}/close`、`.../reopen`、`GET /reviews/{id}` | 合规审查生命周期与冻结/迟到证据对照 |
| `GET /audit/chain` | SHA-256 哈希链完整性校验 |
