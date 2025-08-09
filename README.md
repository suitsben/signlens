# signlens — “What am I *actually* signing?”

**signlens** is a zero-RPC, offline command-line tool that decodes and risk-scores Ethereum calldata
and raw transactions. It recognizes common approval/permit patterns (ERC-20/721/1155), prints a clean,
plain-English explanation, and flags dangerous constructs like **infinite allowances** or
**setApprovalForAll(true)**.

> No internet. No provider. Paste the hex, read the truth.

## Why this exists

Wallet popups and phishing pages often show hex blobs or vague messages. You can copy the calldata or raw
transaction and let **signlens** tell you exactly what will happen — before you sign.

## What it can decode

- **Calldata** (0x...):
  - `approve(address,uint256)`
  - `transfer(address,uint256)`
  - `transferFrom(address,address,uint256)`
  - `setApprovalForAll(address,bool)`
  - `safeTransferFrom(...)` (ERC-721/1155)
  - `permit(address,address,uint256,uint256,uint256,uint8,bytes32,bytes32)` (EIP-2612-style)

- **Raw transactions** (legacy and EIP-1559 typed `0x02`):
  - Gas caps (maxPriorityFee, maxFee), `to`, `value`, and embedded calldata (decoded as above).

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
