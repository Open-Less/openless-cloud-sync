# 应用接入与代码接口交接

状态：待实现接口清单；版本 `1.0-draft.1`。这里定义接手者需要新增或修改的接口，不提供实现代码或架构设计。应用源码路径均相对于 `1-app/openless-all/app/`；本次核对基线为本地 2.0 整合分支的 `f37125da`。

## 1. 现状与替代边界

| 当前入口 | 当前行为 | 新合同要求 |
| --- | --- | --- |
| `src/lib/ipc/cloud-sync.ts` | status/upload/restore/delete 四个手动接口 | 新的加密同步命令族及明确状态机，保留旧协议迁移边界 |
| `src-tauri/src/commands/cloud_sync.rs` | 直接委托 Core，无加密密码参数 | 密码仅以一次性本地 IPC 参数进入 Core；不能调用服务器密码验证 |
| `crates/openless-core/src/cloud_sync.rs` | 使用 Marketplace 登录和 `/me/sync`，发送明文 JSON 快照 | 复用已有 GitHub 登录、独立短期同步会话、加密、版本和幂等语义；仅发送密文 |
| `cloud_sync_types.rs` | 有限 SyncPreferences；排除渠道、密钥和历史 | 新的加密逻辑文档格式；不能在旧 DTO 加 `apiKey` 字段后继续上传 |
| `cloud_sync_validation.rs` | 校验旧明文 DTO、2 MiB 上限 | 新 wire 密文校验与客户端解密后的文档校验分开执行 |
| `cloud_sync_transaction.rs` | 多文件错误回滚，不包含凭据库，也不是跨进程崩溃恢复 | 同一恢复操作协调配置、内存与凭据库，并能在进程退出后继续或回滚 |
| `src/pages/settings/CloudSyncSection.tsx` | 手动备份/恢复/删除、少量状态 | 显式开启、登录、创建/解锁密码、冲突预览、自动同步状态、独立删除 |
| `src/styles/global.css` 的 `.ol-cloud-sync*` | 旧卡片布局 | 标题/说明、账号标签/值、按钮间距保持独立，窄窗不挤在一起；不能用字间距补布局问题 |
| `marketplace.rs` 的 `CLOUD_SYNC_BASE_URL` | 云同步依赖市场主机与固定 9443 端口 | 新服务 origin 独立配置；OAuth client ID 与现有 OpenLess 登录一致；不得误连旧服务后把密钥按旧格式上传 |

旧 `/me/sync` 继续只描述旧手动快照。新用户未同意前不自动迁移。若导入旧备份，先按旧合同校验，在本地与当前数据合并，用户确认后再加密创建新库；旧服务器数据是否删除要单独确认。

## 2. 新的本地 IPC 合同

GitHub 登录统一复用现有 OpenLess OAuth App。已登录时直接在原生层读取已有令牌并交换短期同步会话；下表中的登录命令如保留，只能委托现有登录流程，不创建第二套应用或要求重复授权。退出 OpenLess 账号时同时停止同步、撤销同步会话并清理本机解锁材料。

统一前缀 `cloud_sync_e2ee_*`。旧四个 `cloud_sync_*` 命令不得悄悄改变语义。所有会异步执行网络/磁盘操作的命令返回任务 ID 或状态；“已开始”不能当成“已成功”。

| 命令 | 输入 | 输出与约束 |
| --- | --- | --- |
| `cloud_sync_e2ee_status` | 无 | `EncryptedSyncStatus`；不包含密码、密钥、令牌或密文全文 |
| `cloud_sync_e2ee_begin_sign_in` | 无 | authorizationSessionId、userCode、verificationUri、expiresAt、intervalSeconds；GitHub device code 不返回 UI |
| `cloud_sync_e2ee_poll_sign_in` | authorizationSessionId | pending/signed_in/denied/expired 与公开账号信息；遵守 interval，无后台长期轮询 |
| `cloud_sync_e2ee_cancel_sign_in` | authorizationSessionId | 终止该次登录，丢弃迟到结果 |
| `cloud_sync_e2ee_sign_out` | 无 | 停止自动同步，撤销会话，清理解锁材料；账号隔离的待核对操作保持受保护 |
| `cloud_sync_e2ee_prepare_enable` | consentVersion | 读取新服务能力及元信息，返回 create/unlock/restore_review 所需步骤；不上传 |
| `cloud_sync_e2ee_create` | password、passwordConfirmation、rememberKey、consentVersion、observedRevision | 创建密码并加密首份快照，返回任务 ID；仅在明确允许新建的元信息基线上执行 |
| `cloud_sync_e2ee_unlock` | password、rememberKey | 必须成功验证一份当前密文的 AEAD 标签才返回 unlocked；仅派生密钥成功不算解锁 |
| `cloud_sync_e2ee_lock` | 无 | 清除内存与记住的同步解密密钥，停止自动同步到再次解锁；不删除用户配置 |
| `cloud_sync_e2ee_set_enabled` | enabled | true 要求已完成本机范围确认和解锁/创建流程；false 不删除云端 |
| `cloud_sync_e2ee_sync_now` | 无 | taskId 与当前状态；按统一版本、幂等与冲突流程执行 |
| `cloud_sync_e2ee_cancel` | taskId | 仅取消该任务；上传可能已提交，本地 apply 已开始时必须完成提交或回滚才能返回最终状态 |
| `cloud_sync_e2ee_preview_restore` | observedRevision | previewId、云端版本、本地变更代次、分类数量、需重选的设备设置及脱敏冲突；不返回服务密钥值 |
| `cloud_sync_e2ee_apply_restore` | previewId、mode=replace/merge、conflictChoices | 校验预览仍对应当前账号/云端版本/本地代次；过期返回 stale_preview，不强制应用 |
| `cloud_sync_e2ee_change_password` | currentPassword、newPassword、confirmation、rememberKey | 先处理未确认写入，再按原子 password_change 上传；失败保留恢复所需材料 |
| `cloud_sync_e2ee_delete_remote` | expectedVaultId、observedRevision、confirmed | 用户独立确认删除；使用服务器 CAS 和操作 ID；不删除本机数据 |

`password` 等是一次性 `SecretInput`：普通日志、Debug、遥测和通用错误序列化必须屏蔽；不能纳入命令录制或自动重放。JS 只能持有当前输入框所需的短期字符串，不能保存到 localStorage/sessionStorage。

GitHub 验证地址须由原生层核对为官方 device flow 地址后再交给 UI 打开，不能接受服务端任意 URL。已有 GitHub 授权过期时，仅在实际同步触发中按官方协议续期或要求登录；登录令牌始终排除在同步数据外。

这些本地命令仅允许主窗口/设置窗口的受限能力，不开放给手机输入网页、外部 WebView 或浏览器预览。浏览器 mock 必须返回 unavailable，不能生成“同步成功”假状态。

### 状态与事件 DTO

`EncryptedSyncStatus` 至少包含：

- enabled、authState、keyState、syncState；状态值按需求第 7 节映射。
- account（githubId/login）、vaultId、keyId；未读取时为 null，不用空字符串代替未知。
- localGeneration、lastSyncedLocalGeneration、remoteRevision：十进制字符串。
- lastSuccessfulSyncAt、pendingOperationId、lastError（稳定 code 与脱敏说明）、recoveryRequired。
- hasCloudSnapshot：true/false/null；服务不可用或未读取不能写成 false。

Core 发布 `CloudSyncStateChanged`、`CloudSyncConflictDetected`、`CloudSyncRestoreCompleted` 语义事件，由 Tauri 转译为 `cloud-sync-e2ee:state`、`:conflict`、`:restored`。事件携带 sequence、account/vault 归属及 taskId；注销、换账号、取消后的旧事件必须丢弃。新增事件须同步 `events.rs`、`tauri_events.rs`、typed wrapper 与 `contract/backend-2.0.json`。

冲突 UI 只拿 conflictSetId 和脱敏项目。凭据冲突显示“本机/云端的密钥不同”，选择 local/cloud，不把两把完整密钥回传给 React。服务不提供秘密值差异。

UI 使用稳定 code 对应的本地化错误文本；不能直接显示或记录服务器整段响应。换账号、取消、错误恢复后的诊断也不能泄露密码、令牌或私有数据。

## 3. Core 内部待增加/调整的接口

以下为职责明确的函数合同名；返回类型均留在 Core，不是新增 HTTP 明文接口。

| 接口合同 | 输入 → 输出 | 必须保证 |
| --- | --- | --- |
| `export_sync_documents` | repositories + credentialStore + UI preferences + device profile → SecretSyncDocumentSet | 受控登记、同一逻辑版本、覆盖全部纳入项、不打开客户端提供的任意文件路径 |
| `export_provider_credentials_for_sync` | 受控命名空间/账户登记 → SecretCredentialDocuments | 导出真实密钥而非遮罩；读取失败中止整份导出；排除 OAuth/同步/设备私钥 |
| `validate_sync_documents` | 解密文档 + supportedSchemas → ValidatedSyncDocuments | 类型、限额、引用、未知字段/版本与平台分类校验 |
| `diff_sync_documents` | baseline + local + remote → MergePreview | 稳定 ID 与三方合并；凭据和渠道等依赖按一个单元处理 |
| `prepare_sync_restore` | validated documents + choices + localGeneration → RestorePlan | 预览和目标路径可核验，跨系统档案不直接执行 |
| `apply_sync_restore` | RestorePlan → RestoreReceipt | 凭据库和文件一起取得明确结果；失败保留恢复材料；事件只在最终结果后发出 |
| `recover_sync_restore` | 未完成恢复记录 → completed/rolled_back/recovery_required | 覆盖进程中断，不能靠“删除临时文件”假装恢复完成 |
| `encrypt_sync_snapshot` / `decrypt_sync_snapshot` | secret documents/key + protocol header ↔ SnapshotUpload | 严格按照加密协议；不给 UI 返回密钥或完整凭据明文 |
| `record_sync_change` | origin + logical document IDs + persisted generation → pending status | 保存成功才标脏；恢复来源和无变化写入不再次触发上传 |
| `run_sync_once` | trigger + account/vault scope → task/receipt | 串行提交、冲突处理、幂等核对及上传中新增变更保留 |

现有 `CredentialStore` 只有 read/write/remove、渠道操作和 active-provider 等接口，不能假定它已经支持全库安全导出或原子恢复。应按明确登记的服务账户导出；为批次导入、备份、恢复及失效验证补足合同和平台实现。禁止直接序列化操作系统 keyring/Keystore 数据文件。

## 4. 数据源登记与应用动作

| 逻辑文档 kind | 当前源码入口 | 接手时必须补充 |
| --- | --- | --- |
| preferences / device_profile | `shared_types.rs`、`preferences.rs`、`settings.rs` | 所有 UserPreferences 字段的三类归属表，保留未知键；经 settings effect plan 应用 |
| ui_preferences | `src/i18n/index.ts`、`src/lib/fontScale.ts` | UI 存储导入/导出接口和成功后统一更新事件 |
| channels / provider_credentials | `credentials.rs`、`credentials_legacy.rs`、`provider_resolution.rs`、Host `persistence/credentials.rs` | 同一渠道 ID 的元数据/密钥一致导出；允许账户覆盖、排除令牌列表、失败回滚 |
| dictionary / vocabulary_presets | `vocabulary.rs` 与对应仓储 | 稳定 ID、启用状态、命中/自定义预设的合并及删除标记 |
| corrections | `correction.rs` | 全字段、稳定 ID、删除与修改冲突 |
| style_packs | `style_pack_store.rs`、`style_pack_archive.rs` | 内容、图标与关联 ID；受控资源读取和重新分配本地路径 |
| history | `history.rs`、`types.rs` | 听写/速记全部逻辑字段，音频本机可用性单独计算，避免重复和删除复活 |
| activity | `activity.rs` | 统计的来源 ID/增量去重，不将两设备累计值直接相加 |

不能只监听 preferences.json：凭据写入、渠道排序、历史新增/删除、风格图标、词典等都有自己的持久化入口。需要将 `PreferencesChanged`、`CredentialsChanged`、`HistoryChanged`、`VocabularyChanged`、`StylePacksChanged` 及纠错/活动变更统一纳入；缺少对应“保存成功”事件的仓储应新增事件，而非让 React 猜测写入成功。

旧恢复事务只涵盖部分文件；本批要求在实现阶段补齐崩溃恢复与系统凭据库的一致性，不能把旧事务测试通过当成新要求通过。

## 5. 首次引导和界面间距

- 复用现有服务配置就绪状态，但须区分“配置可读取”“凭据完整”“模型可实际使用”，不以输入框有字符串作为全部就绪。
- 同步询问的本机提示标记、用户范围确认与 enabled 状态不进入远端快照；恢复配置不得替另一台设备自动同意。
- 卡片标题/说明保持明确行距，图标与标题间距 12px、标题与说明 8px、段落与操作区 16px、按钮间距 12px。账号标签和用户名相邻，间距 8px，不用 margin-left:auto 拉到两端。
- 小屏、长用户名、八种界面语言及 125% 字号下检查换行与按钮可达性；不用修改全局 letter-spacing 修复这一块。
- 实时字幕及字幕动画不在本次变更范围。

## 6. 交接完成条件

先完成全部登记、DTO 和接口约束，再分别实现客户端/服务器。联调必须使用 OpenAPI、加密协议互操作向量与需求 A01–A13。所有现有和新增调用点、Tauri command 注册、窗口 capabilities、IPC facade、语义事件及合同测试一起更新。

上线前必须有：真实 GitHub 认证应用归属验证、至少两平台加密互操作、断网/并发/丢响应测试、凭据与文件恢复故障注入、完整排除项检查和开源安全审查。当前文档包没有执行这些实现阶段的验收，也不改变正在运行的旧云同步功能。
