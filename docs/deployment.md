# 部署与运维

更新：2026-09-25。仓库已提供实现和部署脚本；**尚未部署到目标服务器**。此文件描述操作方法，不代表线上状态。

## 部署输入

- Ubuntu/Debian 主机，root 或有等效安装权限的 SSH 账号；已安装 Git、Rust ≥ 1.88、C 编译器、CMake、nginx、Python 3、CA 证书。
- 独立同步域名及其有效 TLS 证书、私钥路径；DNS 指向目标主机，443 可达。客户端使用 HTTPS origin，不带旧服务的 `/me/sync` 路径。
- 专用 GitHub OAuth App，启用 Device Flow，最小身份 scope；client secret 仅进入服务器配置。不得复用市场 OAuth App。
- 用于逐项测试的 GitHub numeric ID。默认 restricted 模式；空白名单关闭登录。

服务器上首次配置：

```bash
sudo install -d -m 0700 /etc/openless-cloud-sync
sudo install -m 0600 deploy/sync.env.example /etc/openless-cloud-sync/sync.env
sudoedit /etc/openless-cloud-sync/sync.env
```

替换两个 OAuth 值，并填写 `SYNC_ALLOWED_GITHUB_IDS`，不要把秘密写入命令参数、Git、聊天或构建输出。项目采用 [AGPL-3.0-only](../LICENSE)，当前默认仅供名单内账号联调；向所有账号开放前完成独立安全审查。

先从官方仓库获取已发布源码：

```bash
git clone https://github.com/Open-Less/openless-cloud-sync.git
cd openless-cloud-sync
git rev-parse HEAD
```

本机验证并部署（按实际值替换参数）：

```bash
bash scripts/deploy.sh SSH_HOST sync.example.com /etc/letsencrypt/live/sync.example.com/fullchain.pem /etc/letsencrypt/live/sync.example.com/privkey.pem
```

本地工作树须已提交且干净，并已推送到官方仓库。脚本将本地 HEAD 的完整 SHA 交给服务器，由服务器直接从 GitHub 检出该提交，执行 locked 测试与 release 构建，不上传本机数据或凭据。可以用第五个参数指定完整 SHA，但本地也须检出同一提交。

安装过程创建独立用户、目录和 systemd 单元，检查 nginx，再启用服务和 HTTPS 虚拟主机。程序按二进制 SHA-256 标识版本，保留 Git 提交号和对应源码归档。首次部署创建数据库，后续保留数据；健康验证失败恢复上个程序及主要代理配置，不覆盖数据库。生产 schema v1；将来有不兼容迁移时必须另行设计迁移和回滚，不能仅回退二进制。

| 位置 | 内容 |
| --- | --- |
| `/opt/openless-cloud-sync/source/` | 从官方 GitHub 仓库检出的指定提交，无生产凭据 |
| `/opt/openless-cloud-sync/releases/`、`current` | 二进制、对应项目源码归档、许可证和当前链接 |
| `/etc/openless-cloud-sync/sync.env` | root:root 0600 配置 |
| `/var/lib/openless-cloud-sync/sync.db` | 单份在线快照、墓碑、回执、会话摘要 |
| `/var/backups/openless-cloud-sync/` | 一致性灾备副本，最长 7 天 |
| `/etc/nginx/sites-available/openless-cloud-sync` | 独立 TLS 虚拟主机 |

## 部署后验证

```bash
systemctl is-active openless-cloud-sync
curl --fail http://127.0.0.1:8787/healthz
curl --fail https://sync.example.com/v1/capabilities
curl --fail https://sync.example.com/revision
systemctl list-timers 'openless-cloud-sync-*'
systemctl status openless-cloud-sync-backup.service openless-cloud-sync-prune.service
```

`/healthz` 仅用于主机本地检查数据库；代理不暴露它。检查能力中的 githubClientId 必须是专用应用。随后执行 [服务端验收](server-acceptance.md)，先真实 GitHub 登录，再逐项测试。客户端应用仍需按 [客户端交接](client-integration.md) 接入，旧应用不能直接调用本接口。

HTTPS 首页提供 `/license`、`/source.tar.gz`、`/revision` 和 `/third-party-notices`。源码归档从同一干净 Git 提交生成，包含构建所需清单、锁文件、源码、迁移、测试和部署脚本，不包含生产配置、数据库或 `.git`。维护修改版时保留这个入口并更新对应源码；它是服务运行版本的源码交付入口。

HTTPS 只在受信任的本机 nginx 终止，服务拒绝非回环连接及缺失 HTTPS 代理头的私有流量。不得对公网开放 8787，不添加跨域通配符，不让额外 CDN 未经核验地覆盖 X-Real-IP。证书续期由已有证书管理器执行并 reload nginx；部署脚本不擅自修改 DNS 或其他站点。

## 备份、到期与恢复

每日 UTC 03:00 一致性备份，每小时清理超过 6 天 23 小时的备份文件；公开上限为 7 天。上线说明应原样公开：“删除云端备份后，在线接口立即不可读，灾备副本最迟 7 天清除。”若供应商还有快照，必须配置同等或更短保留期，不能仅靠本服务的定时器宣称满足。

```bash
sudo -u openless-sync python3 /opt/openless-cloud-sync/current/backup.py
sudo -u openless-sync python3 /opt/openless-cloud-sync/current/backup.py --prune-only
```

备份不含同步会话和 IP 限流记录。到期任务失败须修复；停机仍存在磁盘副本时，同样要清理。不要复制运行中的数据库文件代替 backup API。

灾难恢复必须先停止 API 写入，把候选备份复制到隔离目录执行 `PRAGMA integrity_check`。**不能直接把旧备份当成最新云端状态**：它可能回退版本、丢失删除墓碑或撤销记录。先比对保留下来的最新墓碑/回执或人工确认受影响账号，在解决回退与删除语义后再恢复服务；无法重建的账号保持受限，通知用户用本机数据重新确认。保存故障现场也受 7 天清理期约束。当前没有自动回退数据库的脚本。

## 当前部署阻碍

官网和应用记录已核对，现有 `openless.top` 与 `apic.openless.top` 指向同一主机，官网 HTTPS 可访问；`sync.openless.top` 尚无 DNS 记录。只读连接现有 SSH 别名仍失败（`Permission denied`），本机运维记录指定的私钥文件缺失。需要恢复有效登录入口，再读取服务器证书和站点配置、设置独立同步域名以及专用 OAuth App。未修改现有服务器、市场服务或其数据。
