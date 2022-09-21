use shellbags::{read_all_shell_bags};

pub fn main() {
    unsafe {
        match read_all_shell_bags() {
            Ok(list) => {
                println!("{}", serde_json::to_string_pretty(&list).unwrap());
            },
            Err(e) => {
                println!("{:?}",e);
            }
        }
    }
}