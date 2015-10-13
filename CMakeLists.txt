cmake_minimum_required( VERSION 2.8 )
project( libdigidoc )

set( CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules" )
set( CMAKE_FIND_ROOT_PATH ${CMAKE_OSX_SYSROOT} )
set( INSTALL_DOC false CACHE BOOL "Install documentation" )
set( BUILD_TOOLS true CACHE BOOL "Build digidoc-tool" )
set( BUILD_TYPE "SHARED" CACHE STRING "Build library as SHARED/STATIC" )
if( APPLE )
	set( FRAMEWORK YES CACHE BOOL "Build library as Mac OS X Framework" )
endif()

include( CheckIncludeFiles )
include( VersionInfo )
include( GNUInstallDirs )

if( WIN32 )
	set( DIGIDOC_CONF_NAME "digidoc.ini" )
else()
	set( DIGIDOC_CONF_NAME "digidoc.conf" )
endif()

find_package( Doxygen )
find_package( LibXml2 REQUIRED )
find_package( OpenSSL REQUIRED )
find_package( PKCS11 )
find_package( ZLIB REQUIRED )
find_package( Iconv )

if( INSTALL_DOC )
	if( DOXYGEN_FOUND )
		configure_file( ${CMAKE_SOURCE_DIR}/etc/Doxyfile.in Doxyfile @ONLY )
		add_custom_target( docs ALL
			${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			COMMENT "Generating API documentation with Doxygen" VERBATIM
		)
		install( DIRECTORY ${CMAKE_BINARY_DIR}/doc/ DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/libdigidoc )
	endif()
	install( DIRECTORY doc/ DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/libdigidoc PATTERN ".svn" EXCLUDE )
endif()

configure_file( config.h.cmake config.h )

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${LIBXML2_INCLUDE_DIR}
	${OPENSSL_INCLUDE_DIR}
	${ZLIB_INCLUDE_DIR}
)
if( ICONV_FOUND )
	include_directories( ${ICONV_INCLUDE_DIR} )
endif()

add_subdirectory( libdigidoc )

