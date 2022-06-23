#[macro_use]
extern crate cpython;
pub mod parser;
#[macro_use]
extern crate serde_derive;

use cpython::{PyResult, Python};

fn parse_nessus(_py: Python, val: String) -> PyResult<parser::nessus::report::NessusClientDatav2> {
    let a = parser::nessus::parse(val).unwrap();

    Ok(a)
}

py_module_initializer!(
    neko_libparser,
    initneko_libparser,
    PyInit_neko_libparser,
    |py, m| {
        m.add(py, "__doc__", "This module is implemented in Rust")?;
        m.add(py, "parse_nessus", py_fn!(py, parse_nessus(val: String)))?;
        Ok(())
    }
);
