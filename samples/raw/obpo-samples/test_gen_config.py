# Author: hluwa <hluwa888@gmail.com>
# HomePage: https://github.com/hluwa
# CreateTime: 2022/3/26
import json

from idaapi import *
from obpoplugin.manager import mark_manager_instance
from obpoplugin.process import generate_microcode, prepare_request, _backup_calls

ea = get_screen_ea()
file_name = get_root_filename()
func_name = get_func_name(ea)

func = get_func(ea)
mba = generate_microcode(func)
_backup_calls(mba)

data = prepare_request(mba, mark_manager_instance().func_marked(ea))
data = json.loads(data)

print(json.dumps({
    "func": list(map(int, data["func"].keys()))[0],
    "maturity": data["maturity"],
    "filename": file_name,
    "arch": data["arch"],
    "t": data["t"],
    "bit": data["bit"],
    "is_be": data["is_be"],
    "dispatchers": data["dispatchers"]
}, sort_keys=False, indent=4, separators=(', ', ': ')))
