//! nscope: a lógica pura (`nmap::*`) fica separada da interface (`ui`, `app`) e do I/O (`runner`).
#![forbid(unsafe_code)]

pub mod app;
pub mod i18n;
pub mod nmap;
pub mod report;
pub mod ui;
pub mod util;
