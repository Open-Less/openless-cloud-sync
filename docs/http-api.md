# 云同步 HTTP API v1

状态：待实现合同；版本 `1.0-draft.1`；字段定义以 [openapi.yaml](openapi.yaml) 为机器来源，加密字节格式以 [加密协议](encryption-protocol.md) 为准。

示例基地址为保留域名 `https://sync.openless.example`，**不是已部署地址**。正式域名与 GitHub OAuth client ID 必须在接入前配置、核验；不沿用旧服务 `https://apic.openless.top:9443/me/sync` 的明文合同。

## 1. 通用约束

- 正式环境只接受 HTTPS。客户端不跟随重定向，尤其不能把 Authorization 转发到其他地址。
- JSON 使用 UTF-8、camelCase，拒绝重复 key、未知顶层字段和非法类型。错误也返回 JSON；`204`、`304` 没有响应体。
- 所有私有响应带 `Cache-Control: no-store`；日志不得记录 Authorization、请求/响应密文全文或解密信息。
- 账号只能从经验证的令牌取得。路径和 query 不接受用户指定的账号；请求中的 `ownerGithubId` 只用于和认证身份核对及 AAD 绑定，不决定数据归属。
- revision 是规范十进制字符串，范围为 `0..18446744073709551615`；客户端用整数/BigInt 处理。不是时间戳，不依赖设备时钟。
- `ETag` 是强实体标签，客户端按原样保存并发送，不能去掉引号、自行拼接或解释内部结构。
- JSON 体最大 24 MiB，decoded ciphertext 最大 16,777,232 字节。普通控制接口体最大 8 KiB；限额在读取完整请求前和解析后分别检查。
- 默认单次连接超时 10 秒、请求总时限 60 秒；网络请求取消不等于服务器没有提交。
- 认证交换每 IP 每分钟 20 次；私有读取每账号每分钟 120 次；写/删每账号每分钟 30 次。超额返回 `429` 和 `Retry-After`。可进一步收紧滥用限制，不能放宽协议体积上限。
- 原生客户端使用 Bearer，不使用浏览器 Cookie 作为认证。浏览器 Origin 仅接受明确白名单；CORS 不能替代账号认证。

## 2. 身份流程

### GitHub 登录与云同步令牌是两层

客户端通过专用云同步 OAuth 应用完成 GitHub device flow，仅申请用户身份所需的最小 scope。device code、GitHub access/refresh token 全程留在原生认证层；React 只获得用户码、验证地址、期限和登录状态。遵守 GitHub 返回的 interval、slow_down 和授权过期行为。这是短期登录协议，不是周期同步。[GitHub device flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow)

`POST /v1/auth/github` 的 Bearer 是 GitHub OAuth access token。服务器必须使用配置的 OAuth 应用身份向 GitHub 核验令牌所属应用和有效性，并采用核验结果中的 numeric user ID；不能接受用户名自报、开发身份头或任意其他 OAuth 应用的令牌。GitHub 核验端点为 `POST https://api.github.com/applications/{client_id}/token`，服务端 client secret 不能进入客户端或开源仓库。上游 API 版本固定为当前已核验的 `2026-03-10`，变更须通过合同验证。[GitHub Check a token](https://docs.github.com/en/rest/apps/oauth-applications#check-a-token)

核验成功后只返回一个本服务的短期令牌：

```json
{
  "protocolVersion": 1,
  "accessToken": "OPAQUE_SYNC_TOKEN",
  "tokenType": "Bearer",
  "expiresIn": 900,
  "account": {"githubId": "12345", "login": "example-user"}
}
```

上例令牌是展示占位符，不是可用凭据。同步令牌只授权当前账号的云同步接口，最长 15 分钟，不授权风格市场或 GitHub API。服务端不持久化收到的 GitHub 用户令牌，不把它放入本服务令牌或日志。后续只在实际同步触发时按需重新交换；v1 不提供后台定时刷新或长期同步 refresh token。

`DELETE /v1/auth/session` 立即使当前同步令牌失效，返回 `204`。重复注销已失效令牌返回 `401`，客户端按已退出处理。客户端还必须清理本机同步登录态和记住的解密密钥；GitHub 应用授权本身可由用户在 GitHub 撤销。由于本服务令牌最长 15 分钟，上游撤销到已签发令牌失效存在这个上界，不能宣称瞬时全网撤销。

## 3. 接口总表

| 方法与路径 | 认证 | 输入 | 成功结果 |
| --- | --- | --- | --- |
| `GET /v1/capabilities` | 无 | 无 | `200 Capabilities` |
| `POST /v1/auth/github` | GitHub Bearer | 无 JSON 体 | `200 AuthSession` |
| `DELETE /v1/auth/session` | Sync Bearer | 无 | `204` |
| `GET /v1/me/vault` | Sync Bearer | 可选 If-None-Match | `200 VaultMetadata` 或 `304` |
| `GET /v1/me/vault/snapshot` | Sync Bearer | 必需 If-Match | `200 SnapshotUpload`，仅返回该元信息版本的密文 |
| `PUT /v1/me/vault/snapshot` | Sync Bearer | If-Match、Idempotency-Key、SnapshotUpload | `200 OperationReceipt` |
| `DELETE /v1/me/vault` | Sync Bearer | If-Match、Idempotency-Key、DeleteVaultRequest | `200 OperationReceipt` |
| `GET /v1/me/operations/{operationId}` | Sync Bearer | UUIDv4 操作 ID | `200` 已提交回执、`202` 处理中或 `404` 未找到 |

没有上传明文配置、下载明文密钥、按用户名找备份、服务端解密、找回加密密码或强制覆盖版本的接口。

## 4. 能力与元信息

`Capabilities` 包含协议版本、固定 cryptoProfile、GitHub client ID、协议体积上限、幂等记录保留秒数和灾备最长保留天数。客户端不能因为远端宣称支持弱配置而降级自身最低安全要求。没有此接口或返回不支持的版本时，显示服务不可用/需要升级，不当成空库。

`GET /v1/me/vault` **无论是否已有备份都返回 200**，三个状态：

| state | revision | 其他字段 |
| --- | --- | --- |
| `empty` | `"0"` | vaultId、keyId、updatedAt、lastOperationId、payloadSchemaVersion、ciphertextSha256 为 null，ciphertextBytes=0 |
| `active` | 正数 | 上述字段均有值；含当前密文长度和 SHA-256，但不含解密后的数量或字段名 |
| `deleted` | 保留并递增的正数 | 保留最后 vaultId、updatedAt、lastOperationId；keyId、payloadSchemaVersion、ciphertextSha256=null，ciphertextBytes=0 |

每份元信息含当前 `ownerGithubId` 和 `protocolVersion=1`。响应带 ETag。对该资源的 404 表示路由/协议或服务错误，**不能**表示没有备份。

`GET /snapshot` 必须带刚读取的 ETag：匹配且 active 返回该版本完整加密头与密文；版本变化返回 `412 revision_conflict`；empty/deleted 返回 `404 vault_empty` / `vault_deleted`。服务器不能用另一个版本的密文替代此次绑定的版本。

## 5. 上传与原子前置条件

上传头部与密文结构详见 OpenAPI。HTTP 头 `Idempotency-Key` 必须和 body.operationId 一致；body.revision 必须为 body.baseRevision+1。

处理次序的可观察语义必须是：

1. 先认证与限制请求体积。
2. 在当前账号范围查询操作 ID；已经提交的同一请求返回原回执，**优先于检查当前版本**。
3. 同一个操作 ID 被用于不同方法、路径、If-Match 或请求体，返回 `409 idempotency_key_reused`。Authorization 不计入请求指纹，以便令牌续期后重试同一请求。
4. 新操作核对 ETag、baseRevision、vault/key/salt 和 kind，原子提交密文、递增版本及回执。操作的“已提交”和快照变化不能分开出现。
5. 响应不回传整个密文，只回传该操作的确认结果。

| kind | 允许的当前状态 | 约束 |
| --- | --- | --- |
| `create` | empty / deleted | 新 vaultId、keyId、盐；deleted 状态仍使用其现有 baseRevision，不能归零 |
| `snapshot` | active | vaultId/keyId/盐不变；新 nonce，完整快照 |
| `password_change` | active | vaultId 不变，keyId 与盐必须更换，完整快照同次提交 |

密码是否正确只能由客户端通过解密验证。服务器只核对结构和密码代次，不能返回“密码验证通过”。新普通快照不能修改 key ID 或盐；遇到密码代次改变返回 `409 key_epoch_changed`，客户端保留本地变更并重新解锁。

如果第一次创建发生竞争，只有一份 create 成功；另一方读取胜出的云端库，要求解锁和合并，不能自动换成强制覆盖。

## 6. 操作回执与结果未知

```json
{
  "operationId": "e1d8c32e-d209-4e56-8735-bc66b8684c71",
  "status": "committed",
  "kind": "snapshot",
  "committedRevision": "8",
  "committedAt": "2026-09-23T12:00:00Z",
  "vaultId": "be406ca5-37fa-4b26-9a9a-74c1aad48eae",
  "ciphertextSha256": "4a9f0f4489b2bdc4e6f7e3c1dc95d86694c0ea20a7bb05f27e783a2c6ea9db13"
}
```

上例是结构示例，不对应加密测试向量。删除回执 `kind=delete`，ciphertextSha256=null。

- 成功写/删响应带 `Idempotency-Replayed: true|false`。回执确认的是**该操作曾提交**，不保证其版本仍是云端最新版本。
- 重放的旧回执不能降低客户端已见最高版本，也不能直接覆盖本地当前基线；先读取当前元信息收敛状态。
- 操作 ID 的请求指纹和结果至少保留 **7 天（604800 秒）**。结果查询必须按认证账号隔离，其他账号查询同 ID 返回 404。
- `202` 返回 `{operationId,status:"pending",retryAfterSeconds}`；客户端保留待核对状态，下次有效同步事件再查询或重试同一请求。
- `404 operation_not_found` 不证明原写入一定失败，尤其不排除仍在传输或保留期已过。不能据此生成新 operation ID 盲目重放旧快照。
- 网络超时、断连或响应无法校验时，把请求的**同一密文字节、头部、If-Match、operation ID**保存在本地待处理状态。先查回执或原样重试；保留期外先重新读取并解密当前头，与本地基线和变更合并。

## 7. 删除语义

`DELETE /v1/me/vault` 请求包含 protocolVersion、baseRevision、operationId、expectedVaultId。只允许删除刚读取的 active 库；删除成功使版本加一、移除可读取密文并生成 deleted 元信息与回执。密文和回执状态必须一致。

对 already deleted / empty 的新删除操作分别返回 `409 vault_deleted` / `vault_empty`；相同 operation ID 的重试仍重放原成功回执。其他设备见到 deleted 后暂停自动回写，不能自动重建。注销、关闭同步和删除云端是不同操作。

在线密文立即不可读；灾备清除上限为 30 天，见需求。保留版本墓碑不等于保留用户配置。旧协议备份是不同资源，不受本接口的删除隐式影响；迁移页面要明确说明旧备份是否另行删除。

## 8. 错误合同

格式：`{"error":{"code":"revision_conflict","message":"Cloud snapshot changed.","requestId":"UUID","currentRevision":"8"}}`。message 是简短非敏感说明，不作为程序判断依据；currentRevision 只在相关错误中出现。

| HTTP | code | 客户端行为 |
| --- | --- | --- |
| 400 | invalid_request / unsupported_protocol / invalid_crypto_header | 不重试错误输入，保留数据；未知协议要求升级 |
| 401 | unauthenticated / session_expired | 实际触发时重新交换/登录；不把登录失败当空库 |
| 403 | wrong_oauth_app / owner_mismatch | 停止，检查登录或账号绑定；不改用其他账号 |
| 404 | vault_empty / vault_deleted / operation_not_found | 仅按相应资源语义处理；普通路由404为服务/协议不可用 |
| 409 | idempotency_key_reused / key_epoch_changed / vault_exists / vault_deleted / vault_empty / revision_exhausted | 修正操作、重新解锁或进入用户处理；不强制覆盖 |
| 412 | revision_conflict | 读取新头，解密后三方合并或呈现冲突 |
| 413 | payload_too_large | 不截断、不漏字段，保留未同步状态 |
| 415 | unsupported_media_type | 使用 application/json |
| 428 | precondition_required | 先读元信息，携带 If-Match |
| 429 | rate_limited | 记录 Retry-After，在下一个有效触发处理 |
| 500 / 503 | internal_error / service_unavailable | 读失败保留当前状态；写失败按结果未知核对 |

客户端本地还需要 `weak_password`、`invalid_password_or_ciphertext`、`locked`、`conflict`、`unsupported_document_version`、`recovery_required` 等状态。这些不是服务器知道的密码验证结果。

## 9. 接口联调必须证明

认证应用归属及账号隔离、同名不同 GitHub ID、创建竞争、正常往返、相同 operation ID 重放、不同 body 复用操作 ID、密码变更竞争、下载版本绑定、删除墓碑、超额体积、未知加密配置、取消/超时后的结果核对，以及 HTTP 错误不引起本地数据覆盖。测试用假服务与临时数据，不使用真实用户密钥。
