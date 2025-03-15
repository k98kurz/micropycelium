from micropycelium import Packager
import mpnode

Packager.add_hook('add_peer', mpnode.debug_name('Packager.add_peer'))
Packager.add_hook('add_route', mpnode.debug_name('Packager.add_route'))
Packager.add_hook('set_addr', mpnode.debug_name('Packager.set_addr'))
mpnode.start()
