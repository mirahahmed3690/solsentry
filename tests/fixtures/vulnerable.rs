// A deliberately vulnerable Anchor program, used to test solsentry's detectors.
// Expected findings: missing-signer, unchecked-account, missing-has-one,
// unchecked-math.
use anchor_lang::prelude::*;

#[program]
pub mod vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        // unchecked-math: raw subtraction on a balance can underflow.
        vault.balance = vault.balance - amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // missing-has-one: mutated but not bound to `authority`.
    #[account(mut)]
    pub vault: Account<'info, Vault>,

    // missing-signer + unchecked-account: an authority that no one must sign for
    // and whose owner/contents are never verified.
    pub authority: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub balance: u64,
    pub authority: Pubkey,
}
