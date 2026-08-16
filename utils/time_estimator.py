"""按函数大小粗略预估 CFF 去混淆耗时。

这不是精确计时器，而是给 UI / CLI 的“心理预期”：
实际耗时还受 Binary Ninja 对整个 BinaryView 的重分析、其它插件、机器性能
影响。模型根据 39 基线 + 69 样本的实测量级粗略拟合：

    eta_seconds = base + mlil_blocks / rate

- auto：LLIL copy/split + switch 合成或 deflate 两遍，开销最大；
- general：独立 workflow 无 LLIL copy，批量解析比逐 define 模拟快；
- deflate / switch：单一路径。

返回字符串适合直接放进 UI description 或 logger。
"""


def estimate_seconds(mlil_blocks: int, mode: str = "auto") -> float:
    if mode == "general":
        base, rate = 2.0, 22.0
    elif mode == "switch":
        base, rate = 3.0, 20.0
    elif mode == "deflate":
        base, rate = 3.0, 15.0
    else:  # auto
        base, rate = 4.0, 13.0
    return round(base + mlil_blocks / rate, 1)


def estimate_text(mlil_blocks: int, mode: str = "auto") -> str:
    seconds = estimate_seconds(mlil_blocks, mode)
    if mlil_blocks < 50:
        band = "通常 <10s"
    elif mlil_blocks < 150:
        band = "通常 10-20s"
    elif mlil_blocks < 300:
        band = "通常 20-45s"
    else:
        band = "可能超过 BN 单函数 60s 上限，建议调高 analysis.limits.maxFunctionAnalysisTime"
    return f"约 {seconds}s（{band}）"
