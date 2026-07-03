# Portfolio Blurb

## English

Codex Preflight is a local-first pre-execution safety guard for Codex-style AI coding agents. It
statically scans repositories before risky commands run, classifies the planned command, builds a
best-effort execution graph of reachable scripts/files, detects dangerous capabilities and
uncertainty, and returns ALLOW, WARN, ASK_USER, or BLOCK decisions with JSON/Markdown reports. It
supports local repositories, external GitHub scans, synthetic attack-pattern corpus checks,
trust/cache management, and safe dogfooding workflows. The scanner never executes repository code.

## 中文

Codex Preflight 是一个面向 Codex 类 AI 编程 Agent 的本地执行前安全门。它会在 Agent 执行依赖安装、
脚本、Docker、构建等高风险命令前，静态扫描仓库，识别嵌套 package、脚本链、Docker 配置、MCP
配置、prompt injection、secret、危险 shell pattern，并构建可解释的 execution graph。工具不会执行
仓库代码，只输出 ALLOW / WARN / ASK_USER / BLOCK 决策和 JSON/Markdown 报告。
