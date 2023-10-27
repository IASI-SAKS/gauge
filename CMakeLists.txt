cmake_minimum_required(VERSION 3.12)
project("gauge" LANGUAGES C DESCRIPTION "A simple gauge for your CI provider")
set(CMAKE_C_STANDARD 11)

add_executable(thermo thermo/main.c thermo/rng.c)
