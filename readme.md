# MikuCffHelper

## 1. Introduction

This is a helper for CFF(Control flow flattening). It can help you to deflat the OLLVM CFF obfuscated code.

Use binaryninja workflow to deflat the CFF obfuscated code.

## 2. Installation

Move the folder `MikuCffHelper` to the `plugins` folder of BinaryNinja.

## 3. Usage

Open the CFF obfuscated file with MikuCffHelper_workflow.


1. right click the function you want to deflat, and select `Function Analysis/analysis.plugins.workflow_patch_mlil`.

## todo

this is a beta version, and i'm still working on it.

Only some functions in the example/arm64-v8a.so work well because the feature to trace the source of stateVar assignments has not been implemented yet.

##  原理


原始IL → LLIL优化（代码克隆/条件拆分） 
     → MLIL优化（状态识别/路径消解）
     → HLIL优化（语义恢复）

### ​低级优化层

公共代码块复制（pass_copy_common_block）

If条件内联（pass_inline_if_cond）

分支块独立化（pass_spilt_if_block）

### 中级优化层


基于NetworkX的CFG路径搜索

部分路径模拟执行（emu_hard）

✅ 已实现功能：

控制流平坦化解构
跨架构基础支持
核心优化流水线


⚠️ 已知限制：

需手动选择目标函数
依赖预定义的状态变量特征

(来自2025届本科生正在开发的毕设项目)
