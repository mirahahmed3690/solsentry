// Fixture for the arbitrary-cpi rule: a raw invoke whose target program comes
// from a caller-supplied account. Expected finding: arbitrary-cpi.
use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;

#[program]
pub mod proxy {
    use super::*;

    pub fn forward(ctx: Context<Forward>, data: Vec<u8>) -> Result<()> {
        let ix = build_instruction(&ctx, data);
        // arbitrary-cpi: `target_program` is never checked against a known id.
        invoke(
            &ix,
            &[ctx.accounts.target_program.clone()],
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Forward<'info> {
    pub authority: Signer<'info>,
    /// CHECK: forwarded to
    pub target_program: AccountInfo<'info>,
}
