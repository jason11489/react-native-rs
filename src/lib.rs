use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;

pub type Error = Box<dyn ark_std::error::Error>;

pub mod datatrade;
pub mod gadget;
use crate::datatrade::circuit::test_Data;

#[no_mangle]
pub extern "C" fn add_numbers(a: i32, b: i32) -> i32 {
    a + b
}

#[no_mangle]
pub extern "C" fn hello_world() {
    println!("Hello, /dev/world 1414!");
}

#[no_mangle]
pub extern "C" fn test_circuit() -> bool {
    test_Data()
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
