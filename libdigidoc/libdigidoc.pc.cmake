prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=@CMAKE_INSTALL_FULL_BINDIR@
libdir=@CMAKE_INSTALL_FULL_LIBDIR@
includedir=@CMAKE_INSTALL_FULL_INCLUDEDIR@

Name: libdigidoc
Description: Libdigidoc library for handling digitally signed documents
Version: @VERSION@
Libs: -L${libdir} -ldigidoc
Cflags: -I${includedir}
