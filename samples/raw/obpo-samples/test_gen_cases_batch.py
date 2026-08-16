# Author: hluwa <hluwa888@gmail.com>
# HomePage: https://github.com/hluwa
# CreateTime: 2022/3/26
import os
import json


def inst_info_str(i):
    return "{}. {}".format(i.blk.serial, i.topins.dstr())


def ida_entry():
    import idaapi
    import idc
    from ida_segregs import SR_user
    from obpo.analysis.dispatcher import DispatchAnalyzer
    from obpo.analysis.pathfinder import FlowFinder
    from obpoplugin.manager import mark_manager_instance
    from obpoplugin.process import generate_microcode, prepare_request, _backup_calls

    idaapi.auto_wait()

    CONFIG_PATH = idaapi.get_input_file_path() + ".config.json"
    config = json.loads(open(CONFIG_PATH).read())
    for c in config:
        for ea in c["t"]:
            ea &= ~1
            idc.split_sreg_range(ea, "T", 1, SR_user)
        ea = c["func"]
        idaapi.auto_make_code(ea)
        idaapi.auto_wait()

        file_name = c["filename"]

        _ = list(map(mark_manager_instance().mark, c["dispatchers"]))

        before = idaapi.decompile(ea)

        func = idaapi.get_func(ea)
        mba = generate_microcode(func)
        mba.final_type = False

        c_map = _backup_calls(mba)

        data = prepare_request(mba, mark_manager_instance().func_marked(ea))
        data = json.loads(data)

        analyzer = DispatchAnalyzer(mba=mba)
        for m in mark_manager_instance().func_marked(ea): analyzer.mark_dispatcher(m)
        analyzer.run()
        data.update(analyzer.data())

        finder = FlowFinder(analyzer)
        finder.run()
        data.update(finder.data())
        from obpo.patch.deoptimizer import SplitCommonPatcher
        from obpo.patch.link import FlowPatcher
        from obpo.idahelper import visit_blocks
        from obpoplugin.process import _fixup_calls
        from obpoplugin.process import MBAFixup
        from obpoplugin.manager import mba_manager_instance
        SplitCommonPatcher(finder).run()
        mba.build_graph()
        patcher = FlowPatcher(analyzer)
        for edge, flows in finder.edge4flows().items():
            patcher.run(edge, flows)

        # Clear graph to bypass verify mba
        for b in visit_blocks(mba):
            if b.type in [idaapi.BLT_STOP, idaapi.BLT_XTRN] or b.serial == 0: continue
            b.type = idaapi.BLT_NONE
            b.mark_lists_dirty()

        _fixup_calls(mba, c_map)
        MBAFixup(mba).run()

        mba_manager_instance().cache(mba)

        after = idaapi.decompile(ea, flags=idaapi.DECOMP_NO_CACHE)

        out_name = "{}-{}{}-{}".format(file_name, data["arch"], data["bit"], hex(ea))
        out_path = idaapi.os.path.join(idaapi.os.path.dirname(__file__), "tests", out_name)
        os.makedirs(out_path, exist_ok=True)
        with open(os.path.join(out_path, out_name + ".json"), 'w') as out:
            out.write(json.dumps(data))
        with open(os.path.join(out_path, "original.c"), 'w') as original:
            original.write(str(before))
        with open(os.path.join(out_path, "original_obpo.c"), 'w') as original:
            original.write(str(after))
    exit()


def python_entry():
    import threadpool

    pool = threadpool.ThreadPool(num_workers=64)
    idapath = os.getenv("IDAPATH")

    if not idapath or not os.path.exists(idapath):
        idapath = os.path.join(os.path.dirname(__file__), "ida")
        if not os.path.exists(idapath):
            print("cannot found ida, exiting...")
            exit()

    all_arch = ["arm", "arm64", "x86", "x86_64"]

    def runnable(target):
        os.system("{} -A -S{} {}".format(
            os.path.join(idapath, "ida64" if "64" in arch else "ida"), __file__, target))
        print("{} -A -S{} {}".format(
            os.path.join(idapath, "ida64" if "64" in arch else "ida"), __file__, target))

    def clear():
        for a in all_arch:
            d = os.path.join(os.path.dirname(__file__), a)
            for f in os.listdir(d):
                if f.endswith(".id0") \
                        or f.endswith(".id1") \
                        or f.endswith(".id2") \
                        or f.endswith(".idb") \
                        or f.endswith(".nam") \
                        or f.endswith(".til") \
                        or f.endswith(".i64"):
                    os.remove(os.path.join(d, f))

    clear()
    for arch in all_arch:
        bin_dir = os.path.join(os.path.dirname(__file__), arch)
        for file in os.listdir(bin_dir):
            if not file.endswith(".config.json"): continue

            bin_file = os.path.join(bin_dir, file.removesuffix(".config.json"))
            if not os.path.exists(bin_file):
                print("missing binary {}".format(bin_file))
                continue

            pool.putRequest(threadpool.WorkRequest(runnable, [bin_file]))
    pool.wait()
    clear()


def is_idapython():
    try:
        import idaapi
        return True
    except:
        return False


if is_idapython():
    try:
        ida_entry()
    except:
        exit()
else:
    python_entry()
