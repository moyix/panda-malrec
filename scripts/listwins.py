#!/usr/bin/env python

# Volatility setup boilerplate
import volatility.conf as conf
import volatility.registry as registry
registry.PluginImporter()
config = conf.ConfObject()
import volatility.commands as commands
import volatility.addrspace as addrspace
registry.register_global_options(config, commands.Command)
registry.register_global_options(config, addrspace.BaseAddressSpace)
config.parse_options()

import volatility.plugins.gui.windows as windows

main_desktop = None
def get_windows():
    global main_desktop, config
    winlist = []
    if main_desktop is None:
        # First time. Do the hard work of finding the desktop list and
        # pick the one with the most windows as our "main" desktop
        wplug = windows.Windows(config)
        desktops = []
        for winsta, atom_tables in wplug.calculate():
            for desktop in winsta.desktops():
                num = 0
                for wnd, level in desktop.windows(desktop.DeskInfo.spwnd):
                    num += 1
                    winlist.append(wnd)
                desktops.append( (num, desktop) )
        desktops.sort()
        main_desktop = desktops[-1][1]
    else:
        for wnd, level in main_desktop.windows(main_desktop.DeskInfo.spwnd):
            winlist.append(wnd)
    return winlist

def setup(os, loc):
    global config
    config.PROFILE = os
    config.LOCATION = loc
    # Do one scan to initialize things
    get_windows()

if __name__ == "__main__":
    setup("Win7SP1x86", "qemu:///home/moyix/qemu_pmem.0")

    from IPython import embed
    embed()
