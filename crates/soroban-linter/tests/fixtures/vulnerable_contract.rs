//! Intentionally vulnerable Soroban contract used to test soroban-linter.
//! Every line carrying `// expect: SGxxx` must produce exactly those findings,
//! and no other line may produce any.
#![no_std]
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    Address, BytesN, Env, Vec,
};

const DAY_IN_LEDGERS: u32 = 17280;
const BATCH_SIZE: u32 = 500;

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Owner,
    Counter,
    Members,
    Balance(Address),
    Score(u32),
    Session(Address),
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
        .extend_ttl(&key, DAY_IN_LEDGERS, 30 * DAY_IN_LEDGERS);
}

/// Stores balances in temporary storage: they vanish when the TTL runs out.
fn save_balance_fast(e: &Env, id: &Address, amount: i128) {
    let store = e.storage().temporary();
    store.set(&DataKey::Session(id.clone()), &amount); // expect: SG002
}

fn check_amount(amount: i128) {
    if amount < 0 {
        panic!("negative");
    }
}

fn spend_balance(e: &Env, id: &Address, amount: i128) {
    let b = read_balance(e, id);
    write_balance(e, id, b - amount);
}

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    /// Anyone can call this first and become admin (front-running).
    pub fn initialize(e: Env, admin: Address) { // expect: SG001, SG011
        if e.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        e.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Drains any account: no auth at all, mutation happens in a helper.
    pub fn withdraw(e: Env, from: Address, amount: i128) { // expect: SG001, SG010
        let balance = read_balance(&e, &from);
        write_balance(&e, &from, balance - amount);
    }

    /// Anyone can make themselves admin.
    pub fn set_admin(e: Env, new_admin: Address) { // expect: SG001, SG011
        e.storage().instance().set(&DataKey::Admin, &new_admin);
    }

    /// Anyone can replace the contract code.
    pub fn upgrade(e: Env, new_wasm_hash: BytesN<32>) { // expect: SG001, SG011
        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    /// Owner kept in temporary storage, and no TTL extension anywhere.
    pub fn set_owner(e: Env, owner: Address) { // expect: SG005, SG008, SG011
        owner.require_auth();
        let key = DataKey::Owner;
        e.storage().temporary().set(&key, &owner); // expect: SG002
    }

    pub fn cache_balance(e: Env, user: Address) { // expect: SG005
        user.require_auth();
        let b = read_balance(&e, &user);
        save_balance_fast(&e, &user, b);
    }

    /// Per-player data in instance storage + opaque unwrap.
    pub fn record_score(e: Env, player: Address, round: u32, score: u32) {
        player.require_auth(); // expect: SG008
        let _admin: Address = e.storage().instance().get(&DataKey::Admin).unwrap(); // expect: SG007
        e.storage().instance().set(&DataKey::Score(round), &score); // expect: SG006
    }

    /// Iterates over a member list of unbounded length, reading storage each time.
    pub fn total_balance(e: Env) -> i128 {
        let members: Vec<Address> = e
            .storage()
            .persistent()
            .get(&DataKey::Members)
            .unwrap_or(Vec::new(&e));
        let mut total = 0;
        for m in members.iter() { // expect: SG003
            total += read_balance(&e, &m);
        }
        total
    }

    /// Same problem, hidden in an iterator adapter.
    pub fn sum_scores(e: Env, rounds: Vec<u32>) -> u32 {
        rounds
            .iter()
            .map(|r| e.storage().persistent().get(&DataKey::Score(r)).unwrap_or(0u32)) // expect: SG003
            .sum()
    }

    /// Bounded, but 500 iterations x 2 accesses = 1000 entries > limit.
    pub fn sweep(e: Env, admin: Address) {
        admin.require_auth(); // expect: SG008
        for i in 0..BATCH_SIZE { // expect: SG003
            let key = DataKey::Score(i);
            if e.storage().persistent().has(&key) {
                e.storage().persistent().remove(&key);
            }
        }
    }

    /// `while` loop driven by storage state.
    pub fn drain(e: Env, admin: Address) {
        admin.require_auth(); // expect: SG008
        let mut i = 0;
        while e.storage().persistent().has(&DataKey::Score(i)) { // expect: SG003
            e.storage().persistent().remove(&DataKey::Score(i));
            i += 1;
        }
    }

    /// Intentionally public counter: suppressed inline.
    // soroban-guard: allow(SG001)
    pub fn increment(e: Env) -> u32 {
        let n: u32 = e.storage().instance().get(&DataKey::Counter).unwrap_or(0);
        e.storage().instance().set(&DataKey::Counter, &(n + 1));
        n + 1
    }

    /// Debits `from`, but only the (caller-chosen) `spender` signs.
    pub fn pull(e: Env, spender: Address, from: Address, amount: i128) { // expect: SG001
        spender.require_auth(); // expect: SG008
        check_amount(amount);
        spend_balance(&e, &from, amount);
    }

    /// Loads the admin, then forgets to authorize it.
    pub fn set_fee(e: Env, fee: u32) { // expect: SG001
        let _admin: Address = e.storage().instance().get(&DataKey::Admin).unwrap_or_else(|| panic!()); 
        e.storage().instance().set(&DataKey::Counter, &fee);
    }

    /// Newer SDK upgrade API, still without auth.
    pub fn upgrade_v2(e: Env, hash: BytesN<32>) { // expect: SG001, SG011
        e.deployer()
            .update_current_contract(ContractExecutable::Wasm(hash));
    }

    /// Read-only: never flagged by SG001.
    pub fn balance(e: Env, id: Address) -> i128 {
        read_balance(&e, &id)
    }
}

// ---------------------------------------------------------------------------
// Custom account that accepts any signature.
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone)]
pub enum AccError {
    Unknown = 1,
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
    type Error = AccError;

    fn __check_auth( // expect: SG004
        e: Env,
        _signature_payload: Hash<32>,
        signature: BytesN<64>,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), AccError> {
        let _signer: BytesN<32> = e.storage().instance().get(&WalletKey::Signer).unwrap(); // expect: SG007
        let _ = signature;
        Ok(())
    }
}

// Test code is never linted.
#[cfg(test)]
mod test {
    use super::*;

    fn seed(e: &Env, id: &Address) {
        e.storage().temporary().set(&DataKey::Balance(id.clone()), &100i128);
    }
}
