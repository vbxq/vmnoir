cmake_minimum_required(VERSION 3.21)
project(vmnoir C)

set(CMAKE_C_STANDARD 17)

add_compile_options(-Wall -Wextra)
add_compile_definitions(_WIN32_WINNT=0x0A00)

# fetch libsyscallresolver, a small lib I made
include(FetchContent)
FetchContent_Declare(
    libsyscallresolver
    GIT_REPOSITORY https://github.com/vbxq/libsyscallresolver.git
    GIT_TAG main
)

FetchContent_MakeAvailable(libsyscallresolver)

# ze main executable
add_executable(vmnoir
    src/main.c
    src/engine.c
    src/scanner.c
    src/integrity.c
    src/utils.c
)
target_link_libraries(vmnoir psapi)

# trigger executable (direct syscall, using libsyscallresolver)
add_executable(trigger_direct_syscall
    trigger/main.c
)
target_include_directories(trigger_direct_syscall PRIVATE ${libsyscallresolver_SOURCE_DIR})
