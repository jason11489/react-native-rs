# react-native-rs

write code rust
sh ./scripts/rust_ios.sh

XCode 
1. move ./rust_module/rust_libs to ios/

XCode Setting
1. [ Build Phases ] Link Binary With Libraries
   lib_rust.a

2. [ Build settings ] Search Paths - Library search paths
   $(PROJECT_DIR)/rust_libs

3. [ Build settings ] Search Paths - Header search paths
   "$(PROJECT_DIR)/rust_libs"
