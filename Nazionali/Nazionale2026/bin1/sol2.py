# ANGR BASE TEMPLATE

import angr
proj = angr.Project("./ultima_parola", 
    load_options={"auto_load_libs":False},
    main_opts={"base_addr":0})
init = proj.factory.entry_state()
sim = proj.factory.simulation_manager(init)
s = sim.explore(find=0x401232, avoid=[0x401243, 0x4013E9, 0x40140E, 0x401422])
print(s.found[0].posix.dumps(0).decode(), end="")