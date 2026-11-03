//! A Soroban contract written following best practices.
//! soroban-linter must report nothing for this file.
#![no_std]
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error,
    crypto::Hash,
    symbol_short, Address, BytesN, Env, Symbol, Vec,
};

const DAY_IN_LEDGERS: u32 = 17280;
const BALANCE_BUMP: u32 = 30 * DAY_IN_LEDGERS;
const BALANCE_THRESHOLD: u32 = BALANCE_BUMP - DAY_IN_LEDGERS;
const MAX_BATCH: u32 = 25;

#[contracterror]
#[derive(Copy, Clone)]
pub enum Error {
    NotInitialized = 1,
    BadSignature = 2,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Owner,
    Balance(Address),
    Allowance(Address, Address),
}

#[contractevent]
pub struct AuthorityChanged {
    #[topic]
    key: Symbol,
    value: Address,
}

fn publish_owner_changed(e: &Env, owner: &Address) {
    AuthorityChanged {
        key: symbol_short!("owner"),
        value: owner.clone(),
    }
    .publish(e);
}

fn check_nonnegative_amount(amount: i128) {
    if amount < 0 {
        panic!("negative amount is not allowed: {}", amount)
    }
}

fn read_admin(e: &Env) -> Address {
    e.storage()
        .instance()
        .get(&DataKey::Admin)
        .unwrap_or_else(|| panic_with_error!(e, Error::NotInitialized))
}

fn read_balance(e: &Env, id: &Address) -> i128 {
    e.storage()
        .persistent()
        .get(&DataKey::Balance(id.clone()))
        .unwrap_or(0)
}

fn write_balance(e: &Env, id: &Address, amount: i128) {
    let key = DataKey::Balance(id.clone());
    e.storage().persistent().set(&key, &amount);
    e.storage()
        .persistent()
        .extend_ttl(&key, BALANCE_THRESHOLD, BALANCE_BUMP);
}

fn spend(e: &Env, id: &Address, value: i128) {
    if value <= 0 {
        panic!("value must be positive");
    }
    let b = read_balance(e, id);
    write_balance(e, id, b - value);
}

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn __constructor(e: Env, admin: Address) {
        e.storage().instance().set(&DataKey::Admin, &admin);
        AuthorityChanged {
            key: symbol_short!("admin"),
            value: admin,
        }
        .publish(&e);
    }

    pub fn mint(e: Env, to: Address, amount: i128) {
        check_nonnegative_amount(amount);
        read_admin(&e).require_auth();
        e.storage().instance().extend_ttl(BALANCE_THRESHOLD, BALANCE_BUMP);
        let b = read_balance(&e, &to);
        write_balance(&e, &to, b + amount);
    }

    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        check_nonnegative_amount(amount);
        let fb = read_balance(&e, &from);
        let tb = read_balance(&e, &to);
        write_balance(&e, &from, fb - amount);
        write_balance(&e, &to, tb + amount);
    }

    /// Allowances are short-lived by design, so temporary storage is correct.
    pub fn approve(e: Env, from: Address, spender: Address, amount: i128, live_for: u32) {
        from.require_auth();
        assert!(amount >= 0, "negative allowance");
        let key = DataKey::Allowance(from, spender);
        e.storage().temporary().set(&key, &amount);
        e.storage().temporary().extend_ttl(&key, live_for, live_for);
    }

    /// Bounded batch: at most 25 x 3 entries.
    pub fn batch_balances(e: Env, ids: Vec<Address>) -> Vec<i128> {
        let mut out = Vec::new(&e);
        for id in ids.iter().take(MAX_BATCH as usize) {
            out.push_back(read_balance(&e, &id));
        }
        for i in 0..MAX_BATCH {
            let _ = i;
            let _ = read_admin(&e);
        }
        out
    }

    /// Caller-supplied address, but checked against the stored admin.
    pub fn set_admin(e: Env, caller: Address, new_admin: Address) {
        if caller != read_admin(&e) {
            panic!("not admin");
        }
        caller.require_auth();
        e.storage().instance().set(&DataKey::Admin, &new_admin);
        e.events()
            .publish((symbol_short!("admin"),), new_admin);
    }

    pub fn set_owner(e: Env, caller: Address, owner: Address) {
        if caller != read_admin(&e) {
            panic!("not admin");
        }
        caller.require_auth();
        e.storage().instance().set(&DataKey::Owner, &owner);
        publish_owner_changed(&e, &owner);
    }

    /// Amount validated inside a helper it is forwarded to.
    pub fn burn(e: Env, from: Address, amount: i128) {
        from.require_auth();
        spend(&e, &from, amount);
    }

    /// Spender signs and `from` is debited, but through an allowance.
    pub fn transfer_from(e: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        check_nonnegative_amount(amount);
        let key = DataKey::Allowance(from.clone(), spender);
        let allowance: i128 = e.storage().temporary().get(&key).unwrap_or(0);
        if allowance < amount {
            panic!("insufficient allowance");
        }
        e.storage().temporary().set(&key, &(allowance - amount));
        e.storage().temporary().extend_ttl(&key, 100, 100);
        spend(&e, &from, amount);
        let tb = read_balance(&e, &to);
        write_balance(&e, &to, tb + amount);
    }

    /// Credits `to` without its signature: fine, nothing is taken from it.
    pub fn reward(e: Env, to: Address, amount: i128) {
        read_admin(&e).require_auth();
        check_nonnegative_amount(amount);
        let b = read_balance(&e, &to);
        write_balance(&e, &to, b + amount);
    }

    pub fn upgrade(e: Env, new_wasm_hash: BytesN<32>) {
        e.events()
            .publish((symbol_short!("upgrade"),), new_wasm_hash.clone());
        read_admin(&e).require_auth();
        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    pub fn balance(e: Env, id: Address) -> i128 {
        read_balance(&e, &id)
    }
}

#[contracttype]
pub enum WalletKey {
    Signer,
}

#[contract]
pub struct Wallet;

#[contractimpl]
impl CustomAccountInterface for Wallet {
    type Signature = BytesN<64>;
    type Error = Error;

    fn __check_auth(
        e: Env,
        signature_payload: Hash<32>,
        signature: BytesN<64>,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let signer: BytesN<32> = e
            .storage()
            .instance()
            .get(&WalletKey::Signer)
            .ok_or(Error::NotInitialized)?;
        e.crypto()
            .ed25519_verify(&signer, &signature_payload.into(), &signature);
        Ok(())
    }
}

/// Delegating account: authorization is forwarded, so the payload is
/// legitimately unused here.
#[contract]
pub struct Delegating;

#[contractimpl]
impl CustomAccountInterface for Delegating {
    type Signature = ();
    type Error = Error;

    fn __check_auth(
        env: Env,
        _signature_payload: Hash<32>,
        _signatures: (),
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        for delegate in env.custom_account().get_delegated_signers().iter().take(5) {
            env.custom_account().delegate_auth(&delegate);
        }
        Ok(())
    }
}
