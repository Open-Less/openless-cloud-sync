# OpenLess Cloud Sync

独立的加密云同步后端。客户端先用用户密码加密配置、服务 API 密钥与历史，服务器只保存密文和必要元数据。复用现有 OpenLess GitHub OAuth App 核验身份，以 numeric ID 绑定账号；服务器不接收同步密码、不派生解密密钥。

**当前：服务端 `0.1.0` 已实现并通过本地及 Linux/macOS/Windows CI 验证；服务器部署、真实 OAuth 联调及客户端接入尚未完成。** 协议版本 `1.0-draft.1`，不兼容旧 `/me/sync` 明文合同。

从 [文档入口](docs/index.md) 开始；[架构](docs/architecture.md)、[部署](docs/deployment.md)、[验收](docs/server-acceptance.md) 描述实现与操作。

## 获取与构建

官方仓库：[Open-Less/openless-cloud-sync](https://github.com/Open-Less/openless-cloud-sync)。

```bash
git clone https://github.com/Open-Less/openless-cloud-sync.git
cd openless-cloud-sync
cargo build --release --locked
```

生产部署从这个仓库检出指定提交，在服务器上测试并构建；完整步骤见 [部署](docs/deployment.md)。

## 已实现

- 8 个合同接口：能力、GitHub 换令牌、注销、库元信息、下载、上传、删除、回执查询。
- 900 秒随机会话、账号隔离、严格 JSON、固定加密参数、密文长度及哈希校验。
- 原子 CAS、至少 7 天幂等回执、密码代次与 nonce 防重用、删除墓碑和单份在线快照。
- HTTPS 代理、Origin 白名单、持久化限流、脱敏日志、版本化部署与 7 天备份清理。
- 双实现加密向量、官方 Argon2id 向量、OpenAPI 校验、故障/并发/重启测试。

## 开发与验证

需要 Rust ≥ 1.88、C 编译器和 CMake。Python 验证环境建议 3.14；生产备份脚本只需系统 Python 3.9+。

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --release --locked
python3 -m venv .venv
.venv/bin/python -m pip install -r scripts/requirements-test.lock
.venv/bin/python scripts/interop_vectors.py
.venv/bin/python scripts/check_contract.py
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
.venv/bin/python scripts/smoke_local.py
# 已安装 nginx 时验证真实 TLS 代理
.venv/bin/python scripts/check_nginx.py
cargo audit --deny warnings
```

生产没有开发身份后门，运行必须提供与现有 OpenLess 登录一致的 GitHub OAuth 配置。合成身份仅存在于测试中；真实进程测试只向临时数据库注入一次测试会话。默认 restricted 模式，先用指定账号逐项测试。

## 开源与许可

Copyright (C) 2026 OpenLess contributors.

源码、协议、迁移、部署模板和测试以 **GNU Affero General Public License v3.0 only（AGPL-3.0-only）** 发布，完整条款见 [LICENSE](LICENSE)。本程序不提供担保，详见许可证。第三方依赖保留各自许可证，见 [许可清单](THIRD_PARTY_NOTICES.md)。

部署后的服务首页提供许可证和该运行版本的完整项目源码下载；修改后部署时，同样保留对应源码入口。`publish=false` 仅表示不发布到 crates.io，不影响 GitHub 源码公开。对所有账号开放前仍须完成需求要求的独立安全审查。
