#
# CMakeLists.txt for CORE library
#

# all files named *.c or */cpp are compiled to form the library
file (GLOB_RECURSE CORE_SRC_FILES CONFIGURE_DEPENDS lib/*.c lib/*.cpp lib/utils/*.cpp)

list(APPEND CORE_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include")
list(APPEND CORE_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/lib")
include_directories(${CORE_INCLUDE_DIRS})
set(CORE_INCLUDE_DIRS "${CORE_INCLUDE_DIRS}" CACHE INTERNAL "")


set(CORE_VERSION_MAJOR ${HESEA_VERSION_MAJOR})
set(CORE_VERSION_MINOR ${HESEA_VERSION_MINOR})
set(CORE_VERSION_PATCH ${HESEA_VERSION_PATCH})
set(CORE_VERSION ${CORE_VERSION_MAJOR}.${CORE_VERSION_MINOR}.${CORE_VERSION_PATCH})

add_library(coreobj OBJECT ${CORE_SRC_FILES})
add_dependencies(coreobj third-party)
if (WITH_INTEL_HEXL)
	add_dependencies(coreobj HEXL::hexl)
endif()

set_property(TARGET coreobj PROPERTY POSITION_INDEPENDENT_CODE 1)

if ( BUILD_SHARED )
	add_library (HESEAcore SHARED $<TARGET_OBJECTS:coreobj>)
	set_property(TARGET HESEAcore PROPERTY VERSION ${CORE_VERSION})
	set_property(TARGET HESEAcore PROPERTY SOVERSION ${CORE_VERSION_MAJOR})
	set_property(TARGET HESEAcore PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
	install(TARGETS HESEAcore
		EXPORT HESeaTargets
		DESTINATION lib)
endif()


if( BUILD_STATIC )
	add_library (HESEAcore_static STATIC $<TARGET_OBJECTS:coreobj>)
	set_property(TARGET HESEAcore_static PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
	install(TARGETS HESEAcore_static
		EXPORT HESeaTargets
		DESTINATION lib)
endif()

install(DIRECTORY include/
	DESTINATION include/hesea/core)

add_custom_target( allcore )

if( BUILD_SHARED )
set (CORELIBS PUBLIC HESEAcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
	target_link_libraries (HESEAcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
	add_dependencies( allcore HESEAcore)
endif()

if( BUILD_STATIC )
set (CORELIBS ${CORELIBS} PUBLIC HESEAcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
	target_link_libraries (HESEAcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
	add_dependencies( allcore HESEAcore_static)
endif()

if( BUILD_UNITTESTS )
	file (GLOB CORE_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
	set (CORE_TEST_SRC_FILES ${CORE_TEST_SRC_FILES})
	add_executable( core_tests ${CORE_TEST_SRC_FILES} ${UNITTESTMAIN} )
	set_property(TARGET core_tests PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/unittest)
	target_link_libraries ( core_tests ${CORELIBS} )
	if (NOT ${WITH_OPENMP})
		target_link_libraries ( core_tests PRIVATE Threads::Threads)
	endif()

	add_dependencies( allcore core_tests )

	add_custom_command( OUTPUT runcoretests WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND ${CMAKE_BINARY_DIR}/unittest/core_tests )
	add_custom_target( testcore DEPENDS core_tests runcoretests )
endif()

set( COREAPPS "" )
if ( BUILD_EXAMPLES )
	file (GLOB CORE_EXAMPLES_SRC_FILES CONFIGURE_DEPENDS examples/*.cpp)
	foreach (app ${CORE_EXAMPLES_SRC_FILES})
		get_filename_component ( exe ${app} NAME_WE )
		if (${exe} STREQUAL "parallel" AND NOT ${WITH_OPENMP})
			message("Skipping ${exe} because WITH_OPENMP=OFF")
			continue()
		endif()
		add_executable ( ${exe} ${app} )
		set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/examples/core)
		set( COREAPPS ${COREAPPS} ${exe} )
		target_link_libraries ( ${exe} ${CORELIBS} )
	endforeach()

	add_custom_target( allcoreexamples )
	add_dependencies( allcoreexamples ${COREAPPS} )
	add_dependencies( allcore allcoreexamples )
endif()

set( COREEXTRAS "" )
if (BUILD_EXTRAS)
	file (GLOB CORE_EXTRAS_SRC_FILES CONFIGURE_DEPENDS extras/*.cpp)
	foreach (app ${CORE_EXTRAS_SRC_FILES})
		get_filename_component ( exe ${app} NAME_WE )
		add_executable ( ${exe} ${app} )
		set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/extras/core)
		set( COREEXTRAS ${COREEXTRAS} ${exe} )
		target_link_libraries ( ${exe} ${CORELIBS} )
	endforeach()

	add_custom_target( allcoreextras )
	add_dependencies( allcoreextras ${COREEXTRAS} )
	add_dependencies( allcore allcoreextras )
endif()

add_custom_command( OUTPUT coreinfocmd COMMAND echo Builds HESEAcore and these apps: ${COREAPPS} )
add_custom_target( coreinfo DEPENDS coreinfocmd )

# Collect compile definitions and pass them upward
if ( BUILD_SHARED )
	get_target_property(_compile_defs HESEAcore COMPILE_DEFINITIONS)
	set(_pal_core_compile_defs ${_compile_defs} PARENT_SCOPE)
endif()

if( BUILD_STATIC )
	get_target_property(_compile_defs_static HESEAcore_static COMPILE_DEFINITIONS)
	set(_pal_core_compile_defs_static ${_compile_defs_static} PARENT_SCOPE)
endif()