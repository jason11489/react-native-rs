use std::io::{stdout, BufWriter};

#[no_mangle]
pub extern "C" fn add_numbers(a: i32, b: i32) -> i32 {
    a + b + 1
}

#[no_mangle]
pub extern "C" fn hello_world() {
    println!("Hello, /dev/world 1414!");
}

#[no_mangle]
pub extern "C" fn hello_devworld() {
    let phrase = b"Hello, /dev/world/2019!";
    let stdout = stdout();
    let mut writer = BufWriter::new(stdout.lock());
    ferris_says::say(phrase, 30, &mut writer).unwrap();
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add_numbers(2, 2);
        assert_eq!(result, 4);
    }
}
