set(PKG_VERSION 0.1.0) # increase when you break the API
set(PKG_SOVERSION 0) # increase when you add functionality


# includes
set(PKG_INCLUDE_DIRS 
	prover
	verifier
	issuer
	common
	pcsc
	${CMAKE_BINARY_DIR}
)

# sources
set(SOURCES
	prover/silvia_prover.cpp
	prover/silvia_prover_credgen.cpp
	verifier/silvia_verifier.cpp
	issuer/silvia_issuer_keygen.cpp
	issuer/silvia_issuer.cpp
	common/silvia_rand.cpp
	common/silvia_hash.cpp
	common/silvia_asn1.cpp
	common/silvia_parameters.cpp
	common/silvia_types.cpp
	common/silvia_timer.cpp
	common/silvia_bytestring.cpp
	pcsc/silvia_apdu.cpp
	pcsc/silvia_card.cpp
)

include(DetectArch)
detect_arch()

# dependencies
set(PKG_DEPS libcrypto libpcsclite ${PKG_DEPS})

# verifiy dependencies
find_package(PkgConfig)
pkg_check_modules(DEPS REQUIRED ${PKG_DEPS})

# generate config.h
configure_file(
        ${CMAKE_SOURCE_DIR}/config.h.cmake
        ${CMAKE_BINARY_DIR}/config.h
)

# generate and install pkg-config file
set(DOLLAR "$")
set(PREFIX ${CMAKE_INSTALL_PREFIX})
configure_file(
        ${CMAKE_SOURCE_DIR}/data/${PKG_NAME}.pc.cmake
        ${CMAKE_BINARY_DIR}/data/${PKG_NAME}.pc
)
install(
        FILES ${CMAKE_BINARY_DIR}/data/${PKG_NAME}.pc
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/pkgconfig/
)

# compiler configuration
set(CFLAGS ${DEPS_CFLAGS} ${DEPS_CFLAGS_OTHER})
set(LIBS ${DEPS_LIBRARIES})
set(LIBS ${LIBS} -lgmp)
set(LIB_PATHS ${DEPS_LIBRARY_DIRS})
set(INC_PATHS ${DEPS_INCLUDE_DIRS} ${PKG_INCLUDE_DIRS})

# Compile with -fPIC for MIPS
if(MIPS)
  set(CFLAGS ${CFLAGS} -fPIC)
endif(MIPS)

add_definitions(${CFLAGS})
link_directories(${LIB_PATHS})
include_directories(${INC_PATHS})

# gcc configuration
if(CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fmessage-length=0")
endif(CMAKE_COMPILER_IS_GNUCC)
if(CMAKE_COMPILER_IS_GNUCXX)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmessage-length=0")
endif(CMAKE_COMPILER_IS_GNUCXX)


# generate and install the library
set(INSTALL_LIB_DIR lib CACHE PATH "Installation directory for libraries")
set(INSTALL_BIN_DIR bin CACHE PATH "Installation directory for executables")
set(INSTALL_INCLUDE_DIR include CACHE PATH "Installation directory for header files")
#configure_file(
#        ${CMAKE_SOURCE_DIR}/include/${PKG_NAME}.h.cmake
#        ${CMAKE_BINARY_DIR}/include/${PKG_NAME}.h
#)
add_library(${PKG_NAME} SHARED ${SOURCES} ${SOURCES_common})
target_link_libraries(${PKG_NAME} ${LIBS})
set_target_properties(${PKG_NAME} PROPERTIES
  VERSION ${PKG_VERSION}
  SOVERSION ${PKG_SOVERSION}
#  PUBLIC_HEADER "${CMAKE_SOURCE_DIR}/include/credential.h"
)
install(
  TARGETS ${PKG_NAME}
  LIBRARY DESTINATION ${INSTALL_LIB_DIR} COMPONENT shlib
#  PUBLIC_HEADER DESTINATION ${INSTALL_INCLUDE_DIR}/${PKG_NAME} COMPONENT dev
)

if (BUILD_TESTS)
  add_subdirectory(common/test)
  add_subdirectory(issuer/test)
  add_subdirectory(prover/test)
  add_subdirectory(verifier/test)
  add_subdirectory(test)
  add_subdirectory(pcsc/test)
endif (BUILD_TESTS)
