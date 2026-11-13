# 非解密静态分析演示（demo）

本目录是 `../静态分析方案.md` 的可运行配套。它**只观察、分类、标注不确定性**，
不执行样本、不解密、不提供任何脱壳或 dump 能力。

## 运行

```bash
# 在仓库根目录，使用自带虚拟环境
python3 deliverable/demo/run_demo.py
python3 -m pytest deliverable/demo -q
```

## 文件

- `ranges.py`：文件偏移区间运算、加密覆盖三分类、描述性熵。
- `sample_generator.py`：用 macholib 的 `Structure` 在内存构造 arm64 Mach-O（可选 fat），
  以确定性 PRNG 模拟加密页；提供 `fairplay / conflict / unencrypted / malformed` 四场景。
- `analyzer.py`：复用 macholib 读取路径，输出每架构的结构化报告，所有数据项带
  `coverage` / `certainty` / `parseable` 标记。支持内存字节 `analyze(bytes)` 与
  真实文件 `analyze_path(path)`。
- `run_demo.py`：端到端演示，打印 ASCII 范围关系图并写出 `sample_report.json`。
- `test_static_analysis.py`：区间边界与四场景的不变量测试。

## 关键约定

- 所有区间判断基于**文件偏移**，因为 `LC_ENCRYPTION_INFO` 描述的是磁盘字节窗口。
- `#` = 头部声明加密的字节（只测量不解释）；`-` = 磁盘明文可读；`.` = 区间外。
- 熵仅作描述展示，不用于识别壳；读不到的内容标“不确定”，绝不视为不存在。
