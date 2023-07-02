pub type Error = Box<dyn ark_std::error::Error>;

pub mod datatrade;
pub mod gadget;
use crate::datatrade::circuit::cat;
use crate::datatrade::circuit::test_data;

#[no_mangle]
pub extern "C" fn add_numbers(a: i32, b: i32) -> i32 {
    let mut tmp = 0;
    if test_data() == true {
        tmp = tmp + 1;
    }
    // test_Data();
    a + b + tmp
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
pub extern "C" fn test_circuit() -> bool {
    test_data()
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
