cmake_minimum_required(VERSION 3.5)

project(protocol_parser LANGUAGES CXX C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(/usr/local/include)

link_directories(/usr/lib)
link_directories(/usr/lib64)
link_directories(/usr/local/lib)

aux_source_directory(. SOURCE_FILES)
aux_source_directory(src SOURCE_FILES)
function(main)
    add_executable(${PROJECT_NAME} ${SOURCE_FILES})
    target_link_libraries(${PROJECT_NAME} boost_regex)
endfunction(main)

main()