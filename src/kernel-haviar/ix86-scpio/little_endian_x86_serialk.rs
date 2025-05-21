use std::thread;
use std::time::Duration;

pub trait A { fn a(&self) -> bool; }
pub trait B { fn b(&self) -> bool; }

struct X;
impl A for X {
    fn a(&self) -> bool {
        true
    }
}

struct Y;
impl B for Y {
    fn b(&self) -> bool {
        true
    }
}

/// Basit xor şifre çözme fonksiyonu
fn xor_decode(data: &[u8], key: u8) -> String {
    data.iter().map(|c| (c ^ key) as char).collect()
}

pub struct Z<Aimpl: A, Bimpl: B> {
    a_impl: Aimpl,
    b_impl: Bimpl,
}

impl<Aimpl: A, Bimpl: B> Z<Aimpl, Bimpl> {
    pub fn new(a_impl: Aimpl, b_impl: Bimpl) -> Self {
        Z { a_impl, b_impl }
    }

    pub fn c(&self) {
        let secret_msg_enc: &[u8] = &[33, 43, 43, 41, 44, 35, 7, 39, 38, 44, 46, 33, 45, 44, 33, 48, 44, 39, 44];
        let key = 0x55;

        thread::spawn({
            let a_impl = &self.a_impl;
            let b_impl = &self.b_impl;
            move || loop {
                if !a_impl.a() {
                    if b_impl.b() {
                        let decoded = xor_decode(secret_msg_enc, key);
                        println!("{}", decoded);
                        std::process::exit(1);
                    }
                }
                thread::sleep(Duration::from_secs(5));
            }
        });
    }
}

fn main() {
    let a = X;
    let b = Y;
    let z = Z::new(a, b);
    z.c();

    loop {
        println!("Hello....");
        thread::sleep(Duration::from_secs(10));
    }
}
