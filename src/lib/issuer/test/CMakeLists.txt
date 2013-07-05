set(SOURCES
	issuertest.cpp
	issuetests.cpp
	keygentests.cpp
)

include_directories(..)

add_executable(issuertest ${SOURCES})
add_dependencies(issuertest ${PKG_NAME})
target_link_libraries(issuertest ${LIBS} ${PKG_NAME} ${CPPUNIT_LIBRARIES})

add_test(issuer issuertest)
