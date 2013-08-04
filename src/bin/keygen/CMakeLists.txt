set(KEYGEN_SOURCES
	silvia_keygen.cpp
)

include_directories(. 
	${CMAKE_SOURCE_DIR}/src/lib/issuer
	${CMAKE_SOURCE_DIR}/src/lib/common
	${CMAKE_BINARY_DIR}
)
add_executable(${PKG_NAME}_keygen ${KEYGEN_SOURCES})
add_dependencies(${PKG_NAME}_keygen ${PKG_NAME})
target_link_libraries(${PKG_NAME}_keygen ${LIBS} ${PKG_NAME})

install (TARGETS ${PKG_NAME}_keygen RUNTIME DESTINATION ${INSTALL_BIN_DIR})
