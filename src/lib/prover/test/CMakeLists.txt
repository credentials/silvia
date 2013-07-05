set(SOURCES
	provertest.cpp
	credgentests.cpp
	provetests.cpp
)

include_directories(..)

add_executable(provertest ${SOURCES})
add_dependencies(provertest ${PKG_NAME})
target_link_libraries(provertest ${LIBS} ${PKG_NAME} ${CPPUNIT_LIBRARIES})

add_test(prover provertest)
