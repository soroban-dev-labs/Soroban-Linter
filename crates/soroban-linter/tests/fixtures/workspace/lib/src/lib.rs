//! Library crate in the style of OpenZeppelin Stellar: contract traits with default
//! methods, a `Base` type with the logic, and modules with same-named `storage.rs`.
#![no_std]
use soroban_sdk::{contracttrait, contracttype, Address, Env};

pub mod a;
pub mod b;

#[contracttype]
pub enum LibKey {
    Balance(Address),
}

/// Generic helper: extends whatever key it is given.
pub fn extend(e: &Env, key: &LibKey) {
    e.storage().persistent().extend_ttl(key, 100, 1000);
}

pub struct Base;

impl Base {
    /// Extend-on-read: `Balance` is maintained through the generic helper.
    pub fn balance(e: &Env, id: &Address) -> i128 {
        let key = LibKey::Balance(id.clone());
        let b = e.storage().persistent().get(&key).unwrap_or(0);
        extend(e, &key);
        b
    }

    fn update(e: &Env, id: &Address, value: i128) {
        e.storage().persistent().set(&LibKey::Balance(id.clone()), &value);
    }

    pub fn transfer(e: &Env, from: &Address, to: &Address, amount: i128) {
        from.require_auth();
        if amount < 0 {
            panic!("negative");
        }
        let fb = Base::balance(e, from);
        Base::update(e, from, fb - amount);
        let tb = Base::balance(e, to);
        Base::update(e, to, tb + amount);
    }

    /// Forgot `from.require_auth()`.
    pub fn burn(e: &Env, from: &Address, amount: i128) {
        if amount < 0 {
            panic!("negative");
        }
        let b = Base::balance(e, from);
        Base::update(e, from, b - amount);
    }
}

/// Default methods of a `#[contracttrait]` are contract entry points.
#[contracttrait]
pub trait Token {
    fn transfer(e: &Env, from: Address, to: Address, amount: i128) { // expect: SG014
        Base::transfer(e, &from, &to, amount);
    }

    fn burn(e: &Env, from: Address, amount: i128) { // expect: SG001, SG014
        Base::burn(e, &from, amount);
    }
}
