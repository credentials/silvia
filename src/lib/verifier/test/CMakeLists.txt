set(SOURCES
	verifiertest.cpp
	verifytests.cpp
)

include_directories(..)

add_executable(verifiertest ${SOURCES})
add_dependencies(verifiertest ${PKG_NAME})
target_link_libraries(verifiertest ${LIBS} ${PKG_NAME} ${CPPUNIT_LIBRARIES})

add_test(verifier verifiertest)
