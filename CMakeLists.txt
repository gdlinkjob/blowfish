cmake_minimum_required(VERSION 3.0.0)
project(blowfish VERSION 0.1.0)

enable_testing()

add_library(blowfish blowfish.c)
add_executable(blowfish_test blowfish_test.c)
target_link_libraries(blowfish_test PUBLIC blowfish)

# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
target_include_directories(blowfish_test PUBLIC
                          "${PROJECT_BINARY_DIR}"
                          )

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
