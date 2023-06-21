# react-native-rs

rust ios
========

rust 와 react-native[ios]
device에서 테스트완료



사용법
----


sh ./scripts/rust_ios.sh

* rust_lib
   * lib_rust.a
   * MyRustModule.m
   * rust_module.h   


XCode 
-----

1. cp [./rust_module/rust_libs] to [ios/]

XCode Setting
1. [ Build Phases ] Link Binary With Libraries
   lib_rust.a

2. [ Build settings ] Search Paths - Library search paths
   $(PROJECT_DIR)/rust_libs

3. [ Build settings ] Search Paths - Header search paths
   "$(PROJECT_DIR)/rust_libs"
