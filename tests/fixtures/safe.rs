// The fixed version of vault — solsentry should report zero findings here.
use anchor_lang::prelude::*;

#[program]
pub mod vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        // checked_sub is a method call, not raw arithmetic — not flagged.
        vault.balance = vault
            .balance
            .checked_sub(amount)
            .ok_or(ErrorCode::Underflow)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // bound to the authority via has_one.
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,

    // a real Signer — the caller must prove control.
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub balance: u64,
    pub authority: Pubkey,
}

#[error_code]
pub enum ErrorCode {
    #[msg("arithmetic underflow")]
    Underflow,
}
