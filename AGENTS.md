# OpenLess Cloud Sync

## 范围

本项目是独立的加密云同步服务。需求和对外合同以 [docs/index.md](docs/index.md) 指向的文件为准。服务端为 Rust/Axum + SQLite，应用接入归 `1-app/`；不能把本地测试通过当成已部署、全平台验收或独立安全审查完成。

## 边界

- 云端只接收配置快照的密文。加密密码、派生密钥、配置和服务 API 密钥的明文不得进入服务器接口、日志或运营工具。
- GitHub 仅用于确认账号身份；以 GitHub numeric ID 隔离数据，不能按用户名绑定旧数据。
- 所有密码学原语使用经过审查的实现，不自制算法、不降级明文、不以“永不被攻破”作为产品承诺。
- 这是独立于风格包市场的合同。旧应用 `/me/sync` 不得直接扩展为明文传输 API 密钥的接口。
- 未来服务代码、协议与测试须可开源审查；部署凭据、用户数据和密钥不属于源码。正式开源前必须明确许可证和第三方许可边界。

## 文档维护

需求行为以 `requirements.md` 为准；字段与 HTTP 行为以 `http-api.md` 和 `openapi.yaml` 为准；加密字节格式以 `encryption-protocol.md` 为准；应用改动入口集中于 `client-integration.md`。修改相关合同须同时核对错误码、示例、验收项和相对链接。部署信息归 `docs/deployment.md`，验证证据归 `docs/server-acceptance.md`。

## 开发与验证

从本目录运行 `cargo fmt --check`、`cargo clippy --all-targets --locked -- -D warnings`、`cargo test --locked`。依赖使用 `Cargo.lock`；安全检查为 `cargo audit --deny warnings`。完整验证命令在 README。逻辑在 `src/`，迁移在 `migrations/`，测试在 `tests/`，运维模板在 `deploy/`。

变更不得放宽体积、身份或 HTTPS 边界；不添加开发身份配置或可切换到任意上游的生产认证入口。数据库变更须有原子迁移、故障回滚和兼容验证。生产数据库和环境文件不得进入源码、打包产物或日志。
