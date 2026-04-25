cmake_minimum_required (VERSION 3.10)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("ziovpo-practs")

add_executable (ziovpo-practs WIN32 "ziovpo-practs.cpp" "ziovpo-common.h" "ziovpo-common.cpp" "service-control_c.c")

target_compile_definitions(ziovpo-practs PRIVATE UNICODE _UNICODE)

target_link_libraries(ziovpo-practs PRIVATE
    user32
    shell32
    advapi32
    rpcrt4
)

add_executable(ziovpo-practs-service "ziovpo-service.cpp" "ziovpo-common.h" "ziovpo-common.cpp" "service-control_s.c")
target_compile_definitions(ziovpo-practs-service PRIVATE UNICODE _UNICODE)
target_link_libraries(ziovpo-practs-service PRIVATE advapi32 rpcrt4 wtsapi32 userenv)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ziovpo-practs PROPERTY CXX_STANDARD 20)
endif()