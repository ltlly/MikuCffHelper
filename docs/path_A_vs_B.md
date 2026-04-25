# 路径 A (deflate) vs 路径 B (synthesize_switch) 对比与下一步

针对你的问题："还原为 switch 结构后，是否能更好处理回标准源码？"

## 结论先行

**是的**，但需要追加 post-switch 清理 pass。

- **路径 A (deflate)**：输出**最接近源码**的伪代码（直接 goto 链 → BN 自动结构化为 if/while），但等价性论证依赖 patch 副本，可读性是"已 deflate 但状态变量赋值散落"的中间形态。
- **路径 B (synthesize_switch)**：输出**结构化的 switch-case**，case-graph 显式可见，便于二次分析（dead state 消除 / 单 use case 内联 / 线性链展开）。但 BN HLIL Restructurer 不做这些 case-级别的分析，需要我们补 cleanup pass。

## 实测对比 (sub_407368)

### 原始 (CFF 后, 49 HLIL 行)
```c
x8 = 0xC122D952;
while (true) {
    if (x8 s> 0xe0ee0cb2) {
        if (x8 != 0xe0ee0cb3) {
            if (x8 == 0xe19077be) break;
            if (x8 != 0x7fdcd428) continue;
            // store arg1
            x8 = 0xE00C0E7C;
        }
    }
    if (x8 == 0xad2b5e0d) {
        x8_3 = *var_70;
        // 5 层嵌套状态机...
    }
    // ...
}
return;
```

### 路径 A (deflate, 5 HLIL 行)
```c
sp[-2] = arg1;
free(*(sp - 0x10));   // *(sp-0x10) == sp[-2] == arg1
return;
```

**最接近源码** ← `void f(void* p) { free(p); }` 的真实形态。已在 `docs/audit_407368.md` 手工证明等价。

### 路径 B (synthesize_switch, 47 HLIL 行) — 嵌套 switch 可见
```c
x8 = 0xC122D952;
while (true) {
    switch (x8) {
        case 0x7fdcd428:    // 真实块 1: 把 arg1 存到栈上
            sp[-2] = arg1;
            x8 = 0xE00C0E7C;
            continue;
        case 0xad2b5e0d:    // 真实块 2: 释放
            x8_3 = *var_70;
            while (true) {
                switch (x8_6) {  // 内层 switch
                    case 0x59207abb:
                        free(x8_3);
                        ...
                    case 0xc0835fbf:
                        break;
                }
            }
        case 0xe19077be:    // 终止状态
            break;
    }
}
return;
```

**case 边界清晰，每个 case 是独立逻辑块**。比路径 A 长但更易二次分析。

## 路径 B 启用的下游优化（需要新 pass 实现）

### B.1 死状态消除 (Dead State Elimination)

许多 case 仅做 `state = V; continue`，没有真正副作用。如果 V 对应的 case 只被这一个 case 引用，可以**内联**。

例：原本
```c
case 0x59207abb: free(x8_3); x8_6 = 0xC0835FBF; continue;
case 0xC0835FBF: break;
```
可化简为：
```c
case 0x59207abb: free(x8_3); break;
```

实现：扫描 case 之间的 (state V → target_case) 转移图，找出 in-degree=1 的 case，inline 到唯一 caller。

### B.2 线性链展开 (Linear Chain Inlining)

case 序列 `A → B → C → end` (每个只有一个 successor)，可以展开为顺序代码。

实现：DFS case-graph，标记 in-degree=1 且 out-degree=1 的 case，把链上所有副作用合并成一个块。

### B.3 状态变量消除 (State Variable Elimination)

如果状态变量只在 dispatcher 内部用，case 之间的转移已经表达完整控制流，可以删除所有 `state = V` 赋值。

实现：BN UIDF + dataflow 分析。`func.set_user_var_value(state_var, addr, ...)` 限定取值集，让 BN 知道 state 不会逃逸。

### B.4 case 重排为连续整数

OLLVM 状态值是 32-bit 随机大数（如 0x7fdcd428）。重排为 `case 0, 1, 2, ...` 让 BN 把它当成普通 switch（可能触发 jump-table 优化路径）。

实现：在 jump_to 之前加 `state_idx = encode(state_var)` 转换。

## 路径 B 的局限性

**BN HLIL Restructurer 不会做 B.1-B.3**。它的 transformations 是：
- `&&`/`||` 合并、条件复制、代码复制、子区域解析、jump-table 还原、相邻块合并、goto 插入

**没有 case-graph 级别的语义化简**。所以路径 B 的输出是 `switch (state) { case ...: state = NEXT; continue; ...}` 形式，BN 不会主动把它再化简为 if/while/sequential。

## 建议下一步

按"对源码恢复贡献"排序：

1. **实现 B.1 (死状态消除)** — 收益大，工作量小（O(1 周)）。能把 sub_407368 的内层 switch 化简为 ~10 行。
2. **实现 B.2 (线性链展开)** — 收益中等，工作量小。
3. **实现 B.3 (状态变量消除)** — 收益大但工作量大（涉及 BN UIDF）。
4. **集成 Chisel 风格 program synthesis** — 论文级，覆盖 B.1-B.3 但需重写很大一块。

## 直接答你的问题

> "还原为 switch 结构后，是否能更好处理回标准源码？"

- **路径 B 的 switch 输出本身**：和路径 A 比，没有更接近源码（A 已经把外层最简）
- **路径 B 配合 B.1-B.3 cleanup**：可以让输出 STRUCTURE 上类似源码（switch-tree 还原成 if-tree 等），但 *不会比路径 A 更短*
- **路径 B 的真正价值**：保留了状态机拓扑，便于研究人员**人工**分析 case 之间的逻辑关系；以及为复杂混淆变种（多状态、状态机+memory load）提供分析骨架

**实际研究建议**：两条路径都保留，按场景选：
- 论文里展示"语义等价的最简形态" → 用路径 A，配 manual audit
- 论文里展示"结构保留的去混淆" → 用路径 B
- 实际逆向工作 → 路径 A 看大致流程，路径 B 看分支细节
