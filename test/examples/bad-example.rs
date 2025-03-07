use std::fs::File;
use std::io::{self, Read};
use std::net::TcpStream;
use std::process::Command;
use std::thread;
use std::time::Duration;
use md5;

// Triggers: global_vars (static variable)
static mut GLOBAL_COUNTER: i32 = 5;

// Triggers: exposed_secrets (hardcoded secret)
const API_KEY: &str = "xyz123";

fn main() {
    // Triggers: recursion (recursive call), multiple_returns (two returns)
    println!("{}", factorial(5));

    // Triggers: dynamic_memory (vec!)
    allocate_memory();

    // Triggers: unbounded_loops (loop {}), complex_flow (break)
    infinite_loop();

    // Triggers: async_risk (thread::spawn)
    thread::spawn(|| async_method());

    // Triggers: eval_usage (unsafe block)
    dynamic_code();

    // Triggers: nested_conditionals (nested ifs)
    nested_logic(1, 2);

    // Triggers: unsafe_input (stdin.read_line), unsafe_file_op (File::open)
    read_input();

    // Triggers: network_call (TcpStream::connect)
    make_network_call();

    // Triggers: weak_crypto (md5::compute)
    weak_hash("data");

    // Triggers: unsanitized_exec (Command with concatenation)
    execute_command("test");
}

// Triggers: recursion, multiple_returns
fn factorial(n: i32) -> i32 {
    if n <= 1 { return 1; }
    factorial(n - 1) * n // Recursive call
}

// Triggers: dynamic_memory
fn allocate_memory() {
    let v = vec![0; 100];
    println!("{:?}", v);
}

// Triggers: unbounded_loops, complex_flow
fn infinite_loop() {
    loop {
        unsafe {
            if GLOBAL_COUNTER > 10 { break; }
            GLOBAL_COUNTER += 1;
        }
        return; // Second return
    }
}

// Triggers: async_risk, set_timeout
fn async_method() {
    thread::sleep(Duration::from_secs(1)); // Timing-dependent
    println!("Async operation");
}

// Triggers: eval_usage
fn dynamic_code() {
    unsafe {
        println!("Unsafe operation");
    }
}

// Triggers: nested_conditionals
fn nested_logic(x: i32, y: i32) {
    if x > 0 {
        if y > 0 {
            println!("Nested condition");
        }
    }
}

// Triggers: unsafe_input, unsafe_file_op
fn read_input() {
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer); // Unvalidated input
    let mut file = File::open("file.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents);
}

// Triggers: network_call
fn make_network_call() {
    TcpStream::connect("api.example.com:80"); // No error handling
}

// Triggers: weak_crypto
fn weak_hash(data: &str) {
    let digest = md5::compute(data);
    println!("{:x}", digest);
}

// Triggers: unsanitized_exec
fn execute_command(input: &str) {
    Command::new("sh").arg("-c").arg("echo ".to_string() + input).spawn();
}


let mut s = String::new();
std::io::stdin().read_line(&mut s);    // Triggers: std::io::stdin().read_line (unvalidated stdin)
let mut buf = [0; 1024];
std::net::TcpStream::read(&mut buf);   // Triggers: std::net::TcpStream::read (unvalidated network)
println!("{}", s);                     // Use without validation