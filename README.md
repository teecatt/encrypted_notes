# encrypted_notes

加密笔记数据仓。密文放 `dev`，`master` 作为快照分支发布前端壳。

- `master` : 前端壳 + 历史快照（受保护，禁止 force push / 删除）
- `dev`    : 前端直接提交的加密笔记 `notes.enc.json`

前端通过 raw.githubusercontent.com 从 `dev` 读取密文；`dev` 更新后由 Workflow 追加快照到 `master`。
