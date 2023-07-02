pub type Error = Box<dyn ark_std::error::Error>;

pub mod datatrade;
pub mod gadget;

use crate::datatrade::circuit::cat;
use crate::datatrade::circuit::test_data;
use cocoa::base::nil;
use cocoa::foundation::NSString;
use std::ffi::CString;
#[no_mangle]
pub extern "C" fn add_numbers(a: i32, b: i32) -> i32 {
    // test_Data();
    a + b
}

#[no_mangle]
pub extern "C" fn test_cat(a: i32, b: i32) -> i32 {
    cat(a, b)
}

#[no_mangle]
pub extern "C" fn hello_world() {
    println!("Hello, /dev/world 1414!");
}

#[no_mangle]
pub extern "C" fn test_circuit() -> CString {
    let mut tiger = test_data();
    let c_string = CString::new(tiger.as_bytes()).expect("CString::new failed");
    c_string
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiger_test() {
        test_circuit();
    }

    #[test]
    fn it_works() {
        let result = add_numbers(2, 2);
        println!("{:?}", result);
    }
}
