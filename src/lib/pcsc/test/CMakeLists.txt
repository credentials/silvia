set(SOURCES
	silvia_pcsctest.cpp
)

include_directories(..)

add_executable(silvia_pcsctest ${SOURCES})
add_dependencies(silvia_pcsctest ${PKG_NAME})
target_link_libraries(silvia_pcsctest ${LIBS} ${PKG_NAME} ${CPPUNIT_LIBRARIES})

add_test(pcsc silvia_pcsctest)
