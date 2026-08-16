# Author: hluwa <hluwa888@gmail.com>
# HomePage: https://github.com/hluwa
# CreateTime: 2022/3/26
import json

from idaapi import *
from obpo.analysis.dispatcher import DispatchAnalyzer
from obpo.analysis.pathfinder import FlowFinder
from obpoplugin.manager import mark_manager_instance
from obpoplugin.process import generate_microcode, prepare_request, _backup_calls


def inst_info_str(i):
    return "{}. {}".format(i.blk.serial, i.topins.dstr())


ea = get_screen_ea()
file_name = get_root_filename()
func_name = get_func_name(ea)

func = get_func(ea)
mba = generate_microcode(func)
_backup_calls(mba)

data = prepare_request(mba, mark_manager_instance().func_marked(ea))
data = json.loads(data)

out_name = "mba-{}-{}{}-{}.json".format(file_name, data["arch"], data["bit"], func_name)
analyzer = DispatchAnalyzer(mba=mba)
for m in mark_manager_instance().func_marked(ea):
    analyzer.mark_dispatcher(m)
analyzer.run()
data.update(analyzer.data())

finder = FlowFinder(analyzer)
finder.run()
data.update(finder.data())

out_path = os.path.join(os.path.dirname(__file__), "tests", "testres", out_name)
with open(out_path, 'w') as out:
    out.write(json.dumps(data))
