基本信息
- 项目名称：moonbit-sentinel：mooncakes.io 供应链恶意模块检测器
- 参赛者：（待填写）
- 联系方式：（待填写）
- GitHub 仓库链接：https://github.com/I3eg1nner/moonbit-sentinel
- 项目方向：MoonBit 供应链安全 / 包生态安全基础设施
- 是否为移植项目：否

项目简介
moonbit-sentinel 为 MoonBit 包注册表 mooncakes.io 提供静态恶意模块检测能力，面向包作者、CI/CD 使用方和平台方，识别 typosquatting 之外的真正恶意行为：安装钩子投毒、凭据窃取、混淆载荷投递与二进制后门。项目对注册表全量 3339 个包完成了实测基线（0 确认恶意、84 个 Suspicious 附研判依据），已发布至 mooncakes.io（minie135/moonbit-sentinel@0.4.1）并以 Apache-2.0 开源。

核心功能范围
- 提供行为规则引擎（S01–S10 与 S99 组合规则）：raw-IP 外传端点、凭据路径访问、进程执行、环境变量嗅探、持久化写入；
- 提供 base64 载荷真实解码审查：解码内容含下载器 URL、shell 入口、shebang 时升级 Critical，并以主机形态校验与游程密度识别抑制词表类数据表误报；
- 提供 pre-build 命令链分级：pipe-to-shell、命令替换、base64 解码执行、反弹 shell 特征升级 Critical；
- 提供落地产物检测：ELF/PE/Mach-O 魔数识别、良性扩展名伪装检测、二进制内嵌下载器/反弹 shell 命令字符串扫描；
- 提供风险评分与 Malicious/Suspicious/Clean 判定（≥50/≥15 阈值），--explain 输出逐条可审计的评分分解；
- 提供多格式报告输出：JSON、SARIF 2.1（GitHub Code Scanning 兼容）、Markdown（CI step summary）与 human 摘要；
- 提供 --fail-on suspicious|malicious CI 门禁，verdict 达阈值时非零退出；
- 提供 LLM 研判层（极简智能体）：单次结构化调用 + 一次自纠错重试，输入为预算化证据（引擎结论、findings、命中规则条目），输出 advisory 研判 {verdict, confidence, rationale}，不覆盖引擎结论，模型交互硬上限 20 次/扫描；
- 提供 rules 规则目录子命令，16 条规则的触发条件、示例与缓解建议自描述；
- 提供不少于 100 个 MoonBit 测试（当前 102 个，含单元测试与 5 个 canary 恶意样本端到端断言），并持续保持核心回归测试通过；
- 提供 GitHub Actions CI，覆盖 check、test、wasm/native 构建与引擎自扫描 dogfood；
- 提供 README 示例，覆盖离线 canary 扫描、真实包扫描、SARIF 输出与 CI 集成。
