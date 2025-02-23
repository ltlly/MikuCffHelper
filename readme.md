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


通过binaryninja 的workflow来修改各级il，从而实现去除控制流平坦化

fix_binaryninja_api 通过使用monkey_patch来修改binaryninja的api，从而修复部分bug（如 get_block_at在某些情况下 标准api实现不正确 llil的copy_expr在某些情况下会报错），实现在cpp的api中实现了而在python中未实现的功能（如新增instr的同时指定该instr的地址）

passes/low  实现 复制公共基础块，将if语句放置在单独的block中，内联if(cond) 语句，从而利于在mlil中进行处理
passes/mid  实现 清理Pass（如合并连续的goto，if（true）等语句，合并block，将if（123==a）反转为if(a==123) ）实现将stateVar赋值语句放在当前block尾部，实现将if a!=1 反转为 if a==1, 实现去平坦化

去平坦化: 收集所有为变量赋值为大常数的语句，与if中比较大常数的语句，通过统计学特征来统计出高置信度的stateVar变量，使用nx将cfg抽象为有向有环无权图（唯一入口点，多个出口点），通过nx的路径搜索，得出路径，然后部分模拟执行该路径，如果可达则patch该路径

缺点：应该实现动态追踪stateVar赋值来源，使用更多的特征来收集stateVar，在某些高混淆的情况下，nx搜索出的路径不可达的情况较多，

优点： 相比于D810，性能较优，同时可以处理多层平坦化嵌套的情况
(来自2025届本科生正在开发的毕设项目)
