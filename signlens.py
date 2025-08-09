#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
signlens — decode & risk-score Ethereum calldata / raw txs offline.

Features
- decode-calldata: Identify function by selector and decode params for common ERC20/721/1155 ops:
  * approve(address,uint256)
  * transfer(address,uint256)
  * transferFrom(address,address,uint256)
  * setApprovalForAll(address,bool)
  * safeTransferFrom(...) (721/1155 variants)
  * permit(address,address,uint256,uint256,uint256,uint8,bytes32,bytes32)  [EIP-2612-style]
- decode-tx: Parse legacy and EIP-1559 raw RLP tx (0x-prefixed), show gas caps, value,
  to-address, and analyze calldata like above.
- risk: Heuristics to label HIGH/MEDIUM/LOW risk with human-friendly reasons:
  * Infinite allowance (2**256-1)
  * setApprovalForAll(True)
  * Transfer to a contract creation (to=NULL)
  * Value > 0 + suspicious method mix
- Fully offline. No RPC calls, no internet.

Examples
  $ python signlens.py decode-calldata 0x095ea7b3...      # approve(...)
  $ python signlens.py decode-tx 0x02f8...
  $ python signlens.py risk --calldata 0x095ea7b3... --to 0xSpender

Tip
- You can paste the “Data” hex from a wallet popup, etherscan, or a phishing page to see what it does.
"""

import sys
import json
import math
import click
import rlp
from typing import Dict, Tuple, Optional, List

from eth_utils import keccak, to_checksum_address, is_hex, remove_0x_prefix
from eth_abi import decode as abi_decode

UINT256_MAX = (1 << 256) - 1

# ---- Known function signatures (selectors computed at runtime) ----

KNOWN_SIGS = {
    # ERC-20
    "approve(address,uint256)": ["address", "uint256"],
    "transfer(address,uint256)": ["address", "uint256"],
    "transferFrom(address,address,uint256)": ["address", "address", "uint256"],

    # ERC-721
    "setApprovalForAll(address,bool)": ["address", "bool"],
    "safeTransferFrom(address,address,uint256)": ["address","address","uint256"],
    "safeTransferFrom(address,address,uint256,bytes)": ["address","address","uint256","bytes"],

    # Common permit (EIP-2612 style; selector may vary by token but this covers the canonical signature)
    "permit(address,address,uint256,uint256,uint256,uint8,bytes32,bytes32)":
        ["address","address","uint256","uint256","uint256","uint8","bytes32","bytes32"],
}

def selector_for(sig: str) -> str:
    return "0x" + keccak(text=sig)[:4].hex()

SIGDB: Dict[str, Tuple[str, List[str]]] = {}
for sig, types in KNOWN_SIGS.items():
    SIGDB[selector_for(sig)] = (sig, types)

# ---- Utilities ----

def pretty_value(val_wei: int) -> str:
    # Eth value prettifier (no RPC for price): just ETH formatting.
    if val_wei == 0:
        return "0 ETH"
    eth = val_wei / 10**18
    if eth >= 0.01:
        return f"{eth:.4f} ETH"
    return f"{eth:.10f} ETH"

def chunk_hex(data_hex: str) -> Tuple[str, bytes]:
    if not data_hex:
        return ("", b"")
    h = data_hex.lower()
    if h.startswith("0x"):
        h = h[2:]
    if len(h) < 8:
        return ("", bytes.fromhex(h))
    selector = "0x" + h[:8]
    rest = bytes.fromhex(h[8:])
    return (selector, rest)

def decode_params(types: List[str], data: bytes):
    try:
        return abi_decode(types, data)
    except Exception as e:
        raise ValueError(f"ABI decode error: {e}")

def to_addr(b: bytes) -> str:
    if not b:
        return "0x"
    h = b.hex()
    if len(h) == 0:
        return "0x"
    # Right-pad or ensure last 20 bytes are the address (RLP decode returns raw 20-byte for 'to')
    if len(b) == 20:
        return to_checksum_address("0x"+h)
    # Fallback
    if len(h) >= 40:
        return to_checksum_address("0x"+h[-40:])
    return "0x"+h

def as_int(b: bytes) -> int:
    return 0 if len(b) == 0 else int.from_bytes(b, byteorder="big")

# ---- Core decoding ----

def analyze_calldata(calldata_hex: str) -> Dict:
    sel, payload = chunk_hex(calldata_hex)
    out = {
        "recognized": False,
        "selector": sel,
        "signature": None,
        "decoded": None,
        "explanation": None,
        "flags": []
    }
    if sel in SIGDB:
        sig, types = SIGDB[sel]
        decoded = decode_params(types, payload)
        out["recognized"] = True
        out["signature"] = sig
        out["decoded"] = format_decoded(sig, decoded)
        out["explanation"], flags = explain(sig, decoded)
        out["flags"] = flags
    else:
        out["explanation"] = "Unknown function selector. No decode table match."
    return out

def format_decoded(sig: str, params: Tuple) -> Dict:
    name = sig.split("(")[0]
    fields = []
    if sig == "approve(address,uint256)":
        fields = ["spender", "amount"]
    elif sig == "transfer(address,uint256)":
        fields = ["to", "amount"]
    elif sig == "transferFrom(address,address,uint256)":
        fields = ["from", "to", "amount"]
    elif sig == "setApprovalForAll(address,bool)":
        fields = ["operator", "approved"]
    elif sig == "safeTransferFrom(address,address,uint256)":
        fields = ["from", "to", "tokenId"]
    elif sig == "safeTransferFrom(address,address,uint256,bytes)":
        fields = ["from", "to", "tokenId", "data"]
    elif sig.startswith("permit("):
        fields = ["owner","spender","value","nonce","deadline","v","r","s"]
    else:
        # generic fallback
        fields = [f"arg{i}" for i in range(len(params))]

    as_json = {}
    for k, v in zip(fields, params):
        if isinstance(v, bytes) and len(v) in (20, 32):
            try:
                as_json[k] = to_checksum_address("0x"+v[-20:].hex()) if len(v)==20 else "0x"+v.hex()
            except Exception:
                as_json[k] = "0x"+v.hex()
        elif isinstance(v, (int,)) and k in ("amount","value","tokenId","nonce","deadline"):
            as_json[k] = int(v)
        elif isinstance(v, bool):
            as_json[k] = bool(v)
        else:
            as_json[k] = v.hex() if isinstance(v, (bytes, bytearray)) else v
    return {"name": name, "params": as_json}

def explain(sig: str, params: Tuple):
    flags = []
    text = ""
    if sig == "approve(address,uint256)":
        spender, amount = params
        if isinstance(spender, bytes) and len(spender)==32:
            spender = spender[-20:]
        spender_str = to_checksum_address("0x"+spender[-20:].hex()) if isinstance(spender, (bytes,bytearray)) else str(spender)
        if isinstance(amount, int) and amount == UINT256_MAX:
            flags.append("INFINITE_ALLOWANCE")
            text = f"Approve infinite ERC-20 allowance for {spender_str}."
        else:
            text = f"Approve ERC-20 allowance of {amount} units for {spender_str}."
    elif sig == "transfer(address,uint256)":
        to, amount = params
        to_str = to_checksum_address("0x"+to[-20:].hex()) if isinstance(to, (bytes,bytearray)) else str(to)
        text = f"Transfer {amount} ERC-20 units to {to_str}."
    elif sig == "transferFrom(address,address,uint256)":
        frm, to, amount = params
        frm_str = to_checksum_address("0x"+frm[-20:].hex()) if isinstance(frm,(bytes,bytearray)) else str(frm)
        to_str  = to_checksum_address("0x"+to[-20:].hex()) if isinstance(to,(bytes,bytearray)) else str(to)
        text = f"TransferFrom {amount} ERC-20 units from {frm_str} to {to_str}."
    elif sig == "setApprovalForAll(address,bool)":
        operator, approved = params
        op_str = to_checksum_address("0x"+operator[-20:].hex()) if isinstance(operator,(bytes,bytearray)) else str(operator)
        if approved:
            flags.append("APPROVAL_FOR_ALL")
            text = f"Grant operator {op_str} full control over your NFTs (setApprovalForAll = true)."
        else:
            text = f"Revoke operator {op_str} from controlling your NFTs (setApprovalForAll = false)."
    elif sig.startswith("safeTransferFrom("):
        frm, to, tokenId = params[:3]
        frm_str = to_checksum_address("0x"+frm[-20:].hex()) if isinstance(frm,(bytes,bytearray)) else str(frm)
        to_str  = to_checksum_address("0x"+to[-20:].hex()) if isinstance(to,(bytes,bytearray)) else str(to)
        text = f"Safe transfer NFT tokenId {int(tokenId)} from {frm_str} to {to_str}."
    elif sig.startswith("permit("):
        owner, spender, value, nonce, deadline, *_ = params
        owner_str  = to_checksum_address("0x"+owner[-20:].hex()) if isinstance(owner,(bytes,bytearray)) else str(owner)
        spender_str= to_checksum_address("0x"+spender[-20:].hex()) if isinstance(spender,(bytes,bytearray)) else str(spender)
        if isinstance(value, int) and value == UINT256_MAX:
            flags.append("INFINITE_ALLOWANCE")
        text = (f"Permit signature: owner {owner_str} allows {spender_str} to spend {int(value)} "
                f"(nonce={int(nonce)}, deadline={int(deadline)}).")
    else:
        text = "Unrecognized function."
    return text, flags

# ---- RLP transaction decoding (legacy & EIP-1559 type 0x02) ----

def decode_raw_tx(raw_hex: str) -> Dict:
    h = raw_hex.lower()
    if h.startswith("0x"):
        h = h[2:]
    b = bytes.fromhex(h)

    tx = {"type": "legacy", "fields": {}, "calldata": None}
    if len(b) == 0:
        raise ValueError("Empty tx bytes")

    if b[0] == 0x02:
        # EIP-1559 typed tx: 0x02 || RLP([...])
        payload = b[1:]
        lst = rlp.decode(payload, strict=False)  # list of raw bytes
        # Expected layout per EIP-1559:
        # [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s]
        if not isinstance(lst, list) or len(lst) < 12:
            raise ValueError("Malformed EIP-1559 tx")
        chainId, nonce, maxPrio, maxFee, gas, to, value, data, accessList, v, r, s = lst[:12]
        tx["type"] = "eip-1559"
        tx["fields"] = {
            "chainId": as_int(chainId),
            "nonce": as_int(nonce),
            "maxPriorityFeePerGas": as_int(maxPrio),
            "maxFeePerGas": as_int(maxFee),
            "gasLimit": as_int(gas),
            "to": None if len(to)==0 else to_addr(to),
            "value": as_int(value),
        }
        tx["calldata"] = "0x"+data.hex() if len(data)>0 else None
    else:
        # Legacy
        lst = rlp.decode(b, strict=False)
        if not isinstance(lst, list) or len(lst) < 9:
            raise ValueError("Malformed legacy tx")
        nonce, gasPrice, gas, to, value, data, v, r, s = lst[:9]
        tx["fields"] = {
            "nonce": as_int(nonce),
            "gasPrice": as_int(gasPrice),
            "gasLimit": as_int(gas),
            "to": None if len(to)==0 else to_addr(to),
            "value": as_int(value),
        }
        tx["calldata"] = "0x"+data.hex() if len(data)>0 else None

    return tx

def assess_risk(calldata_info: Optional[Dict], to_addr_str: Optional[str], value_wei: int) -> Dict:
    reasons = []
    score = 0  # 0 low, 50 medium, 100 high

    if value_wei and value_wei > 0:
        reasons.append(f"Sends native value: {pretty_value(value_wei)}.")
        score += 20

    if to_addr_str is None or to_addr_str in ("", "0x"):
        reasons.append("Creates a new contract (to = null).")
        score += 25

    if calldata_info and calldata_info.get("recognized"):
        flags = set(calldata_info.get("flags", []))
        sig = calldata_info.get("signature","")
        if "INFINITE_ALLOWANCE" in flags:
            reasons.append("Infinite ERC-20 allowance detected.")
            score += 70
        if "APPROVAL_FOR_ALL" in flags:
            reasons.append("Grants NFT operator full control (setApprovalForAll = true).")
            score += 70
        if sig.startswith("transfer(") or sig.startswith("transferFrom("):
            reasons.append("Token transfer intent present.")
            score += 15

    # Clamp and label
    score = min(score, 100)
    if score >= 70:
        label = "HIGH"
    elif score >= 30:
        label = "MEDIUM"
    else:
        label = "LOW"

    return {"risk": label, "score": score, "reasons": reasons}

# ---- CLI ----

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """signlens — decode & risk-score Ethereum calldata and raw txs offline."""
    pass

@cli.command("decode-calldata")
@click.argument("calldata_hex", type=str)
def decode_calldata_cmd(calldata_hex: str):
    """
    Decode a hex calldata string (0x...).
    """
    if not calldata_hex or not calldata_hex.startswith("0x") or len(calldata_hex) < 10:
        click.echo("Provide a valid 0x-prefixed calldata hex.", err=True)
        sys.exit(2)
    info = analyze_calldata(calldata_hex)
    click.echo(json.dumps(info, indent=2))
    sys.exit(0)

@cli.command("decode-tx")
@click.argument("raw_tx_hex", type=str)
def decode_tx_cmd(raw_tx_hex: str):
    """
    Decode a raw Ethereum transaction hex (legacy or 0x02 typed).
    """
    try:
        tx = decode_raw_tx(raw_tx_hex)
    except Exception as e:
        click.echo(f"Decode error: {e}", err=True)
        sys.exit(2)

    out = {
        "tx_type": tx["type"],
        "fields": tx["fields"],
        "value_human": pretty_value(tx["fields"].get("value", 0)),
        "calldata": None,
        "calldata_decoded": None
    }
    if tx["calldata"]:
        out["calldata"] = tx["calldata"]
        out["calldata_decoded"] = analyze_calldata(tx["calldata"])
    click.echo(json.dumps(out, indent=2))
    sys.exit(0)

@cli.command("risk")
@click.option("--calldata", "calldata_hex", type=str, default=None, help="0x calldata to assess.")
@click.option("--tx", "raw_tx_hex", type=str, default=None, help="0x raw transaction to assess.")
@click.option("--to", "to_addr_opt", type=str, default=None, help="Spender/recipient address hint (checksum or 0x...).")
def risk_cmd(calldata_hex, raw_tx_hex, to_addr_opt):
    """
    Risk-score either calldata (--calldata) or a raw tx (--tx).
    """
    if not calldata_hex and not raw_tx_hex:
        click.echo("Use either --calldata or --tx.", err=True)
        sys.exit(2)

    cinfo = None
    to_address = None
    value_wei = 0

    if calldata_hex:
        cinfo = analyze_calldata(calldata_hex)
        to_address = to_addr_opt
    else:
        try:
            tx = decode_raw_tx(raw_tx_hex)
        except Exception as e:
            click.echo(f"Decode error: {e}", err=True)
            sys.exit(2)
        to_address = tx["fields"].get("to")
        value_wei = tx["fields"].get("value", 0)
        if tx["calldata"]:
            cinfo = analyze_calldata(tx["calldata"])

    assessment = assess_risk(cinfo, to_address, value_wei)
    out = {
        "input_type": "calldata" if calldata_hex else "tx",
        "to": to_address,
        "value_wei": value_wei,
        "value_human": pretty_value(value_wei),
        "decoded": cinfo,
        "assessment": assessment
    }
    click.echo(json.dumps(out, indent=2))
    # Exit codes could map to risk tiers if desired; keep 0 for success.
    sys.exit(0)

if __name__ == "__main__":
    cli()
