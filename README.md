# 核技术应用许可与流转平台

本项目是一套可离线运行的 Python 服务端平台，用于管理数据中心、互联通道、加速卡资源批次、租户预约、容量分配、交付情景与硬件稳定性准入，以及核技术应用企业的辐射安全许可、场所资质、产品批次与交接流转。业务状态、幂等结果和审计事件保存在 SQLite 中，适合调度、质量、风险和审计人员在单个 Linux 应用容器内协作。

## 目录

- `src/compute_fabric/`：站点、通道、资源库存、预约、容量分配和情景分析；
- `src/accelerator_lab/`：加速卡测点导入、排除复核、分析任务租约和准入决定；
- `src/silicon_qualification/`：AI 加速芯片批次、测量、分析与质量审批；
- `src/license_chain/`：辐射安全许可与范围、场所资质、产品批次、交接授权链与时点合规审查；
- `fixtures/`：离线验收使用的结构化协议与测点；
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
PYTHONPATH=src python3 -m license_chain.acceptance --workspace .
```

这些命令使用临时 SQLite 数据库完成站点、资源、预约、分配、测点分析、芯片准入以及许可授权链全流程（运输→使用→撤销阻断→迟到凭证留痕→结案固化），不访问外部网络。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m compute_fabric.api --database compute.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m accelerator_lab.api --database lab.sqlite3 --host 127.0.0.1 --port 8081
PYTHONPATH=src python3 -m silicon_qualification.api --database silicon.sqlite3 --host 127.0.0.1 --port 8082
PYTHONPATH=src python3 -m license_chain.api --database license.sqlite3 --host 127.0.0.1 --port 8083
```

服务均提供 `GET /health`，其余接口使用 JSON（需带 `X-Actor-Id` 头）。进程重启后可以继续查询 SQLite 中的业务状态和审计历史。

## 许可与流转授权链（license_chain）

授权链由四类凭证拼成：**许可证（含许可范围）→ 场所资质 → 产品批次 → 交接单**，据此重建某批次在任一历史时点能否由指定单位运输、使用或转交。

### 双时态模型

每张凭证同时携带两个时间：

- **业务日期**（`valid_from/valid_to/qualified_on/occurred_on/added_on`）：事实在现实中何时生效，按它重放历史；
- **录入时刻**（`recorded_at`，服务时钟）：系统何时知道该事实，用于识别补录的迟到凭证（`late_entry`）。

许可在业务日 `d` 有效，当且仅当 `valid_from ≤ d ≤ valid_to` 且撤销生效日晚于 `d`。因此：

- **撤销只向未来生效**：阻止撤销生效日之后的流转，不删除或改写此前已合法完成的交接；
- **事后补登的许可范围不能追认历史**：范围条带 `added_on`，按业务日过滤；
- **迟到凭证不静默翻案**：已结案（closed）的合规审查固化证据快照与 SHA-256，迟到交接单只会在 `new_evidence` 中留痕（`evidence_changed=true`），结论与快照不变；未结案（open）审查可调用 `refresh` 重算。

每次交接评估返回具体授权依据 `bases`（许可证号+范围条+场所资质单号）和缺失环节 `gaps`，代码如 `actor.license_revoked`、`scope.not_covered`、`site.qualification_expired`、`chain.custody`、`custody.not_holder`。

### 主要接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/licenses`、`/licenses/{id}/scopes`、`/licenses/{id}/revoke` | 许可批文、范围条目、宣告撤销 |
| POST | `/sites`、`/sites/{id}/revoke` | 场所资质登记与撤销 |
| POST | `/batches` | 产品批次登记（初始场所须属于持有人） |
| POST | `/handovers` | 交接登记（`transport`/`use`/`transfer`），合法 `recorded`、否则 `rejected` 但留痕 |
| GET | `/authorization?batch_id&unit_id&action&on` | 时点授权判定 |
| GET | `/batches/{id}/chain` | 批次保管链全量追溯 |
| POST | `/reviews`、`/reviews/{id}/close`、`/reviews/{id}/refresh` | 合规审查开立、结案固化、未结案重算 |
| GET | `/reviews/{id}` | 审查结论、证据哈希完整性与迟到证据 |
| GET | `/audit/chain` | SHA-256 哈希链校验 |
