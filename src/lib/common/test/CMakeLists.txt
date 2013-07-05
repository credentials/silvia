set(SOURCES
	commontest.cpp
	typetests.cpp
	hashtests.cpp
	syspartests.cpp
	randtests.cpp
)

include_directories(..)

add_executable(commontest ${SOURCES})
add_dependencies(commontest ${PKG_NAME})
target_link_libraries(commontest ${LIBS} ${PKG_NAME} ${CPPUNIT_LIBRARIES})

add_test(common commontest)
