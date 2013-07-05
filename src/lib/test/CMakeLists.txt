set(SOURCES
	silviatest.cpp
	issuetests.cpp
	proveverifytests.cpp
)

add_executable(silviatest ${SOURCES})
add_dependencies(silviatest ${PKG_NAME})
target_link_libraries(silviatest ${LIBS} ${PKG_NAME} ${CPPUNIT_LIBRARIES})

add_test(silvia silviatest)
