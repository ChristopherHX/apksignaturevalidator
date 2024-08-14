project(ApkSignValidator)

add_executable(ApkSignValidator main.cpp)
target_link_libraries(ApkSignValidator ssl crypto)