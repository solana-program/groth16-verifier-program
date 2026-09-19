//! The README's registration-and-verification example, runnable.
//!
//! Three parties appear, and the code below is grouped by which one acts:
//!
//! 1. **The application** runs the trusted setup, keeps the proving key
//!    off-chain, publishes the verifying key on-chain, and advertises the
//!    canonical key address.
//! 2. **A user** obtains the proving key and verifying key from wherever the
//!    application distributes them, and checks — without trusting the
//!    application — that the verifying key hashes to the advertised address.
//! 3. **A consuming program** hardcodes the advertised address, checks that
//!    the account it was handed is that address, and CPIs `Verify`.
//!
//! Every transaction is executed as a real Solana message (the harness's
//! `run_atomic`, over Mollusk's `process_transaction_instructions`), so the
//! instructions the README says must share a transaction really do share one
//! here. Read it top to bottom; `program/tests/common` supplies only the
//! harness and assertions, not the flow.

mod common;

use {
    common::{assert_success, assert_tx_success, harness, Harness},
    groth16_convert::{arkworks, gnark, OnChainKey, OnChainProof},
    mollusk_svm::{program::keyed_account_for_system_program, result::types::TransactionResult},
    solana_account::Account,
    solana_address::Address,
    solana_groth16_verify::{
        constants::{staging_account_len, MAX_PUBLIC_INPUTS},
        instruction as ix,
        state::{key_account_len, DISCRIMINATOR_KEY},
    },
    solana_instruction::Instruction,
};

/// A client's view of the ledger: the accounts it knows about, updated after
/// every transaction. `None` in the account slot means "does not exist yet".
struct Ledger {
    accounts: Vec<(Address, Account)>,
}

impl Ledger {
    fn new(accounts: Vec<(Address, Account)>) -> Self {
        Self { accounts }
    }

    /// Submits one transaction and applies its effects.
    fn submit(&mut self, h: &Harness, instructions: &[Instruction]) -> TransactionResult {
        let result = h.run_atomic(instructions, &self.accounts);
        assert_tx_success(&result);
        for (address, account) in &result.resulting_accounts {
            match self.accounts.iter_mut().find(|(a, _)| a == address) {
                Some(slot) => slot.1 = account.clone(),
                None => self.accounts.push((*address, account.clone())),
            }
        }
        result
    }

    fn account(&self, address: &Address) -> &Account {
        &self
            .accounts
            .iter()
            .find(|(a, _)| a == address)
            .unwrap_or_else(|| panic!("{address} unknown"))
            .1
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../tools/fixtures/gnark/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Chunk size for `Write`. A transaction carries about 1,100 bytes of
/// instruction data after one signature and two account keys, so a key body
/// of `448 + 64·(n+1)` bytes takes `⌈body / 800⌉` upload transactions.
const CHUNK: usize = 800;

#[test]
fn readme_walkthrough() {
    let Some(h) = harness() else { return };
    let mollusk = &h.mollusk;
    let program_id = h.program_id;

    // ======================================================================
    // 1. The application: trusted setup, publish the verifying key.
    // ======================================================================

    // `groth16.Setup` (gnark) or `generate_random_parameters` (arkworks) gives
    // a proving key and a verifying key. The proving key is large and stays
    // off-chain — the application hosts it wherever it likes. The verifying
    // key is what goes on-chain; here it is the gnark fixture's `vk.bin`.
    let vk_file = fixture("vk.bin");
    let vk: OnChainKey = gnark::parse_verifying_key(&vk_file).expect("gnark verifying key");
    let n = vk.num_public_inputs();
    assert!(n <= MAX_PUBLIC_INPUTS);

    // Check off-chain what `Publish` will check on-chain, before paying for
    // any transaction. Conversion alone accepts keys that `Publish` would not.
    vk.validate_for_publish().expect("publishable key");

    // The canonical address is a function of the key alone. The application
    // computes it now and this is the address it advertises to everyone.
    let (advertised_key_address, _bump) = ix::find_key_address(&program_id, &vk.hash());

    // Two application keypairs: `authority` owns the staging account during
    // the upload and gets its rent back; `payer` funds the canonical account.
    // They may be the same key; they are kept apart here to show which signs
    // what. `staging` is a throwaway keypair for the upload buffer.
    let authority = Address::new_unique();
    let payer = Address::new_unique();
    let staging = Address::new_unique();
    // Accounts that do not exist yet (`staging`, and later the canonical
    // address) are listed as empty system accounts so the runtime loads them;
    // on a live cluster the RPC does this for the client.
    let mut ledger = Ledger::new(vec![
        (authority, wallet(10_000_000_000)),
        (payer, wallet(10_000_000_000)),
        (staging, Account::default()),
        keyed_account_for_system_program(),
    ]);

    // --- Transaction 1: create and claim the staging account ----------------
    //
    // `create_staging` returns `CreateAccount ‖ InitializeStaging` as a pair.
    // They must be in the same transaction: `InitializeStaging` cannot tell
    // who paid for the account, so a gap between the two would let anyone
    // claim it. `authority` signs `InitializeStaging`; `payer` and `staging`
    // sign `CreateAccount`.
    let rent = mollusk.sysvars.rent.minimum_balance(staging_account_len(n));
    let tx1 = ix::create_staging(&program_id, &payer, &authority, &staging, n as u16, rent);
    ledger.submit(&h, &tx1);
    assert_eq!(ledger.account(&staging).owner, program_id);
    assert_eq!(ledger.account(&staging).data.len(), staging_account_len(n));

    // --- Transactions 2..k: upload the body in chunks -----------------------
    //
    // Only `authority` may write, so these can be spread over any number of
    // transactions without anyone else being able to interfere. One `Write`
    // per transaction here; several may share one when they fit.
    let uploads = ix::write_body(&program_id, &authority, &staging, vk.body(), CHUNK);
    assert_eq!(uploads.len(), vk.body().len().div_ceil(CHUNK));
    for write in &uploads {
        ledger.submit(&h, std::slice::from_ref(write));
    }

    // --- Transaction k+1: publish -------------------------------------------
    //
    // `Publish` validates every point, checks that the body hashes to the
    // canonical address, creates the canonical account at its final size,
    // copies the body in, and closes staging — refunding its rent to
    // `authority`. Nobody else can create an account at this address.
    let authority_before = ledger.account(&authority).lamports;
    let publish = ix::publish(
        &program_id,
        &authority,
        &payer,
        &staging,
        &advertised_key_address,
    );
    ledger
        .accounts
        .push((advertised_key_address, Account::default()));
    ledger.submit(&h, std::slice::from_ref(&publish));

    let key_account = ledger.account(&advertised_key_address);
    assert_eq!(key_account.owner, program_id);
    assert_eq!(key_account.data.len(), key_account_len(n));
    assert_eq!(key_account.data[0], DISCRIMINATOR_KEY);
    assert_eq!(&key_account.data[8..], vk.body());
    // Staging is gone and its rent came back to the authority.
    assert_eq!(ledger.account(&staging).lamports, 0);
    assert!(ledger.account(&staging).data.is_empty());
    assert_eq!(ledger.account(&authority).lamports, authority_before + rent);

    // ======================================================================
    // 2. A user: check the distributed key against the advertised address.
    // ======================================================================

    // The user downloads the proving key and verifying key from the
    // application. They do not trust the download: they parse the verifying
    // key themselves and recompute the address. If it matches what the
    // application advertised (and what the consuming program hardcodes), the
    // key they hold is the key the chain verifies against. There is nothing
    // else to check — the address *is* the commitment.
    let downloaded_vk = gnark::parse_verifying_key(&fixture("vk.bin")).expect("downloaded vk");
    let (recomputed, _) = ix::find_key_address(&program_id, &downloaded_vk.hash());
    assert_eq!(recomputed, advertised_key_address);

    // Two things the chain cannot check remain with the user, both host-side.
    // Whether the verifying key is the setup's output for the *intended
    // circuit* is checked against the ceremony transcript, if there is one;
    // the address commits to the bytes but says nothing about which circuit
    // they came from. Whether the *proving* key matches the verifying key is
    // checked with arkworks by comparing `pk.vk` against the downloaded key,
    // or with gnark by proving a known witness and verifying it under the
    // downloaded key. The fixture ships only the proof the generator produced,
    // so that step is represented by the proof and public inputs below.
    let proof: OnChainProof = gnark::parse_proof(&fixture("proof.bin")).expect("proof");
    let public_inputs = arkworks::public_inputs(
        &gnark::parse_public_witness(&fixture("public.bin")).expect("public witness"),
    );

    // ======================================================================
    // 3. A consuming program: pin the address, then verify.
    // ======================================================================

    // The consuming program hardcodes `EXPECTED_KEY` — the same constant a
    // Solidity contract would hold as a verifier address. Before the CPI it
    // checks the key account it was handed *is* that address. The verifier
    // itself only checks ownership and the discriminator; the address check
    // is what binds the proof to this circuit and it belongs to the caller.
    let expected_key: Address = advertised_key_address;
    let handed_in: (Address, Account) = (
        advertised_key_address,
        ledger.account(&advertised_key_address).clone(),
    );
    assert_eq!(handed_in.0, expected_key, "wrong circuit");

    // `Verify` is a single instruction: the key account, and
    // `proof ‖ public_inputs` as data. Here it is called top-level; a program
    // would `invoke` the same instruction.
    let verify = ix::verify(&program_id, &handed_in.0, &proof.0, &public_inputs);
    let result = mollusk.process_instruction(&verify, std::slice::from_ref(&handed_in));
    assert_success(&result);

    // A proof for the same statement with one public input changed fails
    // with code 6, "well-formed proof that does not verify".
    let mut wrong = public_inputs.clone();
    wrong[2][31] ^= 1;
    let verify = ix::verify(&program_id, &handed_in.0, &proof.0, &wrong);
    let result = mollusk.process_instruction(&verify, std::slice::from_ref(&handed_in));
    common::assert_custom_error(&result, common::code::PROOF_INVALID);
}

fn wallet(lamports: u64) -> Account {
    Account {
        lamports,
        data: vec![],
        owner: ix::SYSTEM_PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}
