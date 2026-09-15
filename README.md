# encrypted_notes

加密笔记子站（n.down2.top）的前端壳与数据仓。

## 分支模型

- `master`：前端壳 + 历史快照（受保护，禁止 force push / 删除）
- `dev`：前端直接提交的加密笔记数据（受保护的密文分支）

## 当前数据模型（schema v4）

- **内容**：每篇笔记一个扁平文件，路径 = `notes/<加密文件名>`；文件内容 = `base64(iv(16B) || AES-CTR-256(magic \n order \n title \n markdown))`。
- **文件名**：`base64url(iv(16B) || AES-CTR-256(id \n title \n ancestors))`，标题与祖先链一并隐藏；同明文复用同一随机 IV，保证稳定且不碰撞。
- **新格式（N2）**：自本次加固起，内容改为 `N2:base64(iv || ct || HMAC-SHA256(iv||ct))`；HMAC 密钥由 Argon2 IKM 经 HKDF（info=`notes-mac-v1`）派生，与 AES 密钥分离。旧格式仍可解密，无需迁移。
- **清单**：`tree.json` 只保存加密文件名数组，查看器据此列目录，**0 次 GitHub API**。
- **缓存**：IndexedDB 保存 params / 明文 / tree / 本地版本时间线；加密密钥（enc + mac）与 GitHub token 也存 IndexedDB，`lock` 时一并清除。

## KDF 与参数

- 参数外置于公开仓 `teecatt/encrypted_params` 的 `params.json`（Argon2id、m=256MiB、t=4、p=1、hashLen=32），便于审计与统一调参。
- 派生优先自托管 WASM（`vendor/argon2-bundled.min.js`），失败回退 `@noble/hashes`。

## 读取与写入

- 读取：优先 `raw.githubusercontent.com`（带缓存参数），失败回退 GitHub Trees API（可选 token），再失败回退 jsDelivr；写入使用 Git Trees API，sha 失效自动重取重试。

## 部署

- `master` push 后由 `.github/workflows/deploy-cloudflare.yml` 发布到 Cloudflare Pages 项目 `encrypted-notes`。
