import json

with open(
    r"C:\\Users\\ltlly\AppData\\Roaming\\Binary Ninja\\plugins\\cfg_analysis.json",
    "r",
) as f:
    data = json.load(f)

new_data = []


for func in data:
    if func["branch_complexity"]==0:
        continue
    if func["if_instr_len"]==0:
        continue
    if func["avg_out_degree"]==0:
        continue
    if func["mlil_instructions_len"]> 1000:
        continue
    new_data.append(func)

# 根据 cyclomatic_complexity 降序排序
new_data.sort(key=lambda x: x["cyclomatic_complexity"], reverse=True)


print(f"Processed {len(new_data)} functions.")

with open(
    r"C:\\Users\\ltlly\AppData\\Roaming\\Binary Ninja\\plugins\\cfg_analysis_processed.json",
    "w",
) as f:
    json.dump(new_data, f, indent=4)
print(new_data)