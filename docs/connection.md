# 客户端连接信息

更新：2026-09-26。**连接配置已确定，正式服务等待 OAuth Client Secret 配置后启动。** 服务器已从公开仓库完成构建、16 项 Rust 测试、隔离 HTTPS 验证和备份测试；这不代表公网服务已经上线。

| 项目 | 值 |
| --- | --- |
| HTTPS origin | `https://apic.openless.top:9443` |
| 能力探测 | `GET https://apic.openless.top:9443/v1/capabilities` |
| GitHub OAuth App | 现有 `OpenLess`，复用应用里的 GitHub 登录 |
| OAuth Client ID | `Ov23liyv3nEucG7oMHNE`（公开标识，可放客户端） |
| 协议 | `protocolVersion=1`，合同 `1.0-draft.1` |
| 加密配置 | `argon2id-xchacha20poly1305-v1` |
| 同步会话有效期 | 900 秒，由原生层按需要交换 |

客户端不能包含 OAuth Client Secret；它仅存在服务器的 root 专用环境配置中。用户的同步密码和派生密钥留在设备端，不发送到认证或同步接口。

## 接入顺序

1. 读取能力，核对协议、加密配置及 Client ID。
2. 复用已有 OpenLess GitHub 令牌调用 `POST /v1/auth/github`。已有登录有效时不再次弹出 GitHub 授权。
3. 后续调用使用返回的短期同步令牌；先 `GET /v1/me/vault` 获取当前状态与 ETag。
4. 按 [HTTP 合同](http-api.md) 和 [加密协议](encryption-protocol.md) 创建、下载、更新或删除密文快照。完整字段与错误码以 [OpenAPI](openapi.yaml) 为准。

| 操作 | 路径 |
| --- | --- |
| 读取库元信息 | `GET /v1/me/vault` |
| 按版本下载快照 | `GET /v1/me/vault/snapshot`，必须携带 `If-Match` |
| 创建、更新或改密码 | `PUT /v1/me/vault/snapshot`，CAS 和操作 ID 按合同校验 |
| 删除云端快照 | `DELETE /v1/me/vault`，需要用户确认、CAS 和操作 ID |
| 核对未知写入结果 | `GET /v1/me/operations/{operationId}` |
| 注销同步会话 | `DELETE /v1/auth/session` |

旧 `/me/sync` 明文请求不能连接此服务。客户端完成加密接入后，再按 [验收顺序](server-acceptance.md) 逐项联调；未确认同步范围前不得上传用户数据。
