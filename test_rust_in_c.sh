set -e


#copy rust library => test_rust_in_c.dir
cp ./target/debug/librust_module.a ./test_rust_in_c

#run test code c
gcc ./test_rust_in_c/test.c ./test_rust_in_c/librust_module.a -lSystem -lresolv -lc -lm -o test_code_with_c

#run test_code
./test_code_with_c