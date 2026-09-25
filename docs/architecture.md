# 服务端架构

更新：2026-09-23；实现版本 `0.1.0`；wire 合同仍为 `1.0-draft.1`。

## 进程与存储

专用 HTTPS nginx 虚拟主机 → 回环地址上的 Axum 服务 → 本机 SQLite。独立于市场服务，没有 `/me/sync` 路由、跨项目数据库或客户端恢复能力。客户端密码学只出现在互操作测试中，服务运行依赖不包含 Argon2 或 XChaCha20 解密实现。

| 文件 | 职责 |
| --- | --- |
| `src/server.rs` | 认证前后边界、HTTPS 代理、Origin 白名单、体积/超时/并发限制、HTTP 路由、脱敏日志 |
| `src/auth.rs` | 现有 OpenLess GitHub OAuth App 核验、numeric ID、900 秒随机同步令牌 |
| `src/protocol.rs` | 严格 DTO、uint64 十进制版本、UUIDv4、固定 cryptoProfile、规范 base64url、密文哈希和长度 |
| `src/store.rs` | CAS、原子快照和回执、删除墓碑、nonce/盐/ID 重用保护、会话、持久化滑动窗口限流 |
| `src/config.rs` | 环境配置和启动时校验；生产只绑定回环地址 |
| `migrations/001_initial.sql` | SQLite schema v1；启动事务迁移，拒绝读取未来版本 |
| `scripts/`、`deploy/` | 验证、备份与清理、版本化部署、systemd 与 nginx 配置 |

每个账号最多保留一个可读取快照。元信息为 empty/active/deleted；empty 的 revision 为 0，其他状态继续递增，删后重建也不归零。版本作为十进制文本保存、按 Rust `u64` 校验，不依赖 SQLite 有符号整数或 JavaScript 浮点数。

所有写入用 `BEGIN IMMEDIATE`，在同一事务中检查回执、比较版本、写入快照/墓碑及回执。操作 ID 只在账号内唯一。请求指纹覆盖方法、路径、原始 If-Match 和原始 body 字节；更换访问令牌不改变指纹。相同请求优先重放原回执，body 空格变化也属于不同请求。失败事务不会留下 nonce 或部分快照。SQLite 在专用阻塞线程中执行，HTTP 取消后已经开始的事务可以完成，客户端必须核对结果。

服务同步提交，不建立持久化 pending 队列；当前通常返回 200 committed 或 404 operation_not_found。合同的 202 供未来异步实现使用。404 仍不能证明仍在传输的操作没有提交。

## 认证与数据边界

GitHub `POST /applications/{client_id}/token` 使用现有 OpenLess OAuth App 的 client ID/secret 和固定 `2026-03-10` API 版本，禁止重定向。只使用核验响应中的 numeric user ID，额外核对 app.client_id 和有效期。上游 404 不能区分无效令牌与其他应用令牌，统一返回 401；成功响应中应用不一致返回 403 wrong_oauth_app。上游应用凭据失效或限流返回 503，不冒充用户登录失败。

GitHub 用户令牌不入库。同步令牌来自操作系统随机数，32 字节，仅保存 SHA-256 和 900 秒期限。注销删除当前 hash。生产二进制没有开发身份头、假登录、上游 URL 覆盖或服务端密码接口。默认 restricted 模式只允许显式列出的 GitHub ID；没有名单时无人可登录，public 模式须显式配置。

JSON 直接反序列化到严格 DTO，拒绝重复字段、未知字段、错误类型和不符合协议的数字。校验前不执行 KDF。服务器只能验证加密封装，不能证明恶意客户端所传字节确实经过正确加密，也不能确认密码正确。

日志只含请求随机 ID、状态、耗时及固定故障事件，不含 URI、账号、IP、Authorization、请求体或上游响应。nginx 禁用访问日志、关闭请求与响应磁盘缓冲，覆盖而非追加客户端提供的代理身份头。错误 body 的 requestId 与应用 X-Request-Id 一致；代理拒绝请求时单独生成 UUIDv4 格式诊断 ID。

## 限额与生命周期

HTTP 体 24 MiB，控制接口 8 KiB，密文最多 16,777,232 字节；校验长度、65536 字节填充块和 SHA-256。服务最多同时处理 8 个请求；nginx 每 IP 8 条、该服务总计 32 条连接。总请求时限 60 秒；GitHub 连接 10 秒、请求 30 秒。部署的 1 GiB 服务内存上限适用于初期小规模运行；扩容前用真实快照分布压测。

认证每 IP 20 次/滚动 60 秒，私有读取每账号 120 次，写/删每账号 30 次。限流记录在 SQLite 中，重启不清零；不信任客户端传入的 IP。幂等结果至少保留 7 天；后台维护只清理服务自身过期记录，不发起客户端同步任务。

SQLite 使用 FULL synchronous、DELETE journal、secure_delete，避免 WAL 和空闲页长留旧密文。删除后的在线 API 即刻不可读，回执和墓碑无正文。只保存盐/库 ID/密码代次/nonce 的不可逆承诺用于防重用，无历史快照读取接口。

灾备副本通过 SQLite backup API 获取一致视图，不备份登录会话。默认每日备份、每小时清理，删除阈值为 6 天 23 小时，给公开的 7 天上限留出运行余量。停止服务器、云盘快照、额外备份或人工复制时，运行方须继续执行同样的到期清理；此服务无法清理未知的供应商副本。

参考：[GitHub token 核验](https://docs.github.com/en/rest/apps/oauth-applications#check-a-token)、[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)、[libsodium XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)。
