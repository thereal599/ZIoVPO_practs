cmake_minimum_required (VERSION 3.10)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("ziovpo-practs")

if (MSVC)
    add_compile_options(/utf-8)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(RPC_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated-rpc")
set(RPC_IDL "${CMAKE_CURRENT_SOURCE_DIR}/service-control.idl")
set(RPC_HEADER "${RPC_GEN_DIR}/service-control.h")
set(RPC_CLIENT "${RPC_GEN_DIR}/service-control_c.c")
set(RPC_SERVER "${RPC_GEN_DIR}/service-control_s.c")

add_custom_command(
    OUTPUT "${RPC_HEADER}" "${RPC_CLIENT}" "${RPC_SERVER}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${RPC_GEN_DIR}"
    COMMAND midl /nologo /env x64 /out "${RPC_GEN_DIR}" "${RPC_IDL}"
    DEPENDS "${RPC_IDL}"
    COMMENT "Generating Windows RPC stubs with MIDL"
)

add_custom_target(generate_rpc DEPENDS "${RPC_HEADER}" "${RPC_CLIENT}" "${RPC_SERVER}")

add_executable(ziovpo-practs WIN32
    "ziovpo-practs.cpp"
    "ziovpo-common.h"
    "ziovpo-common.cpp"
    "${RPC_CLIENT}"
)
add_dependencies(ziovpo-practs generate_rpc)
target_include_directories(ziovpo-practs PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}" "${RPC_GEN_DIR}")
target_compile_definitions(ziovpo-practs PRIVATE UNICODE _UNICODE)
target_link_libraries(ziovpo-practs PRIVATE user32 shell32 advapi32 rpcrt4 comdlg32 ole32)

add_executable(ziovpo-practs-service
    "ziovpo-service.cpp"
    "ziovpo-common.h"
    "ziovpo-common.cpp"
    "${RPC_SERVER}"
)
add_dependencies(ziovpo-practs-service generate_rpc)
target_include_directories(ziovpo-practs-service PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}" "${RPC_GEN_DIR}")
target_compile_definitions(ziovpo-practs-service PRIVATE UNICODE _UNICODE)
target_link_libraries(ziovpo-practs-service PRIVATE advapi32 rpcrt4 wtsapi32 userenv winhttp iphlpapi bcrypt)
