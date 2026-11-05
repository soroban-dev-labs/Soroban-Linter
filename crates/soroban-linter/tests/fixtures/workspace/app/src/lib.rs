//! Contract crate using the library.
#![no_std]
use lib::{a, b, Base, Token};
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum AppKey {
    Note(u32),
}

#[contract]
pub struct App;

#[contractimpl]
impl App {
    /// `a::on_hook` debits `token`, which never signs.
    pub fn hook_a(e: Env, token: Address, amount: i128) { // expect: SG001, SG014
        a::on_hook(&e, &token, amount);
    }

    /// `b::on_hook` is read-only: nothing to authorize.
    pub fn hook_b(e: Env, token: Address, amount: i128) {
        b::on_hook(&e, &token, amount);
    }

    /// Calls a library function with its own name.
    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) { // expect: SG014
        Base::transfer(&e, &from, &to, amount);
    }

    /// `Note` entries are never extended anywhere.
    pub fn note(e: Env, author: Address, id: u32) { // expect: SG005
        author.require_auth();
        e.storage().persistent().set(&AppKey::Note(id), &author);
    }
}

#[contractimpl]
impl Token for App {}
