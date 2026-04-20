# ANGR BASE TEMPLATE

import angr
proj = angr.Project("./mappa", 
    load_options={"auto_load_libs":False},
    main_opts={"base_addr":0})
init = proj.factory.entry_state()
sim = proj.factory.simulation_manager(init)
s = sim.explore(find=0x12F5, avoid=[0x12C3, 0x1306])
print(s.found[0].posix.dumps(0).decode(), end="")