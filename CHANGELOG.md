### Unreleased
#### Features
* Make error types implement `std::error::Error`.
#### Maintenance
* Update code to Rust 2021 edition.
* Bump a number of dependencies to current versions.
* Apply `clippy` fixes.
* Simplify `mstsc-rs` command-line parsing.
#### Bug fixes
* Fix potential truncated read in `core::per::read_padding`.
* Fix potential truncated write in `<Vec<u8> as Message>::write`.
* Fix potential truncated write in `model::link::Stream::write` (now renamed).
* Fix multiple potential truncated/oversized reads in `nla::cssp::cssp_connect`.

### 0.1.1 (2020-04-11)
#### Features
* Remove dependency of `rust-crypto`.
* Fix parameter name.
* Fix overflow in packet computation.

### 0.1.0 (2020-04-11)
#### Features
* Initial release.
