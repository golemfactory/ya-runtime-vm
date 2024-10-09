#[macro_export]
macro_rules! die {
    ($expr:expr) => {
        unsafe {
            libc::sync();

            loop {
                eprintln!("Error: {:?}", $expr);
                libc::reboot(libc::RB_POWER_OFF);
                std::arch::asm!("hlt");
                unreachable!();
            }
        }
    };
}

#[macro_export]
macro_rules! check {
    ($expr:expr) => {
        if $expr == -1 {
            panic!("Error: {:?}", $expr);
        }
    };
}

#[macro_export]
macro_rules! check_result {
    ($expr:expr) => {
        if $expr.is_err() {
            die!($expr);
        }
    };
}

#[macro_export]
macro_rules! check_bool {
    ($expr:expr) => {
        if !$expr {
            crate::die!($expr);
        }
    };
}
