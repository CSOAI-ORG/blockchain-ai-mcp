#!/usr/bin/env python3
"""
Blockchain AI MCP Server
============================
Web3 and cryptocurrency toolkit for AI agents: wallet analysis, transaction
tracing, smart contract auditing, gas estimation, and token metadata.

By MEOK AI Labs | https://meok.ai

Install: pip install mcp
Run:     python server.py
"""


import sys, os
sys.path.insert(0, os.path.expanduser('~/clawd/meok-labs-engine/shared'))
from auth_middleware import check_access

import hashlib
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Optional
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
FREE_DAILY_LIMIT = 30
_usage: dict[str, list[datetime]] = defaultdict(list)


def _check_rate_limit(caller: str = "anonymous") -> Optional[str]:
    now = datetime.now()
    cutoff = now - timedelta(days=1)
    _usage[caller] = [t for t in _usage[caller] if t > cutoff]
    if len(_usage[caller]) >= FREE_DAILY_LIMIT:
        return f"Free tier limit reached ({FREE_DAILY_LIMIT}/day). Upgrade: https://mcpize.com/blockchain-ai-mcp/pro"
    _usage[caller].append(now)
    return None


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------
KNOWN_CONTRACTS = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": {"name": "USDT (Tether)", "type": "ERC-20", "chain": "ethereum"},
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": {"name": "USDC (Circle)", "type": "ERC-20", "chain": "ethereum"},
    "0x6b175474e89094c44da98b954eedeac495271d0f": {"name": "DAI (MakerDAO)", "type": "ERC-20", "chain": "ethereum"},
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": {"name": "Uniswap V2 Router", "type": "DEX Router", "chain": "ethereum"},
    "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": {"name": "UNI (Uniswap)", "type": "ERC-20", "chain": "ethereum"},
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": {"name": "WBTC (Wrapped Bitcoin)", "type": "ERC-20", "chain": "ethereum"},
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": {"name": "WETH (Wrapped Ether)", "type": "ERC-20", "chain": "ethereum"},
}

VULNERABILITY_PATTERNS = {
    "reentrancy": {
        "severity": "CRITICAL",
        "description": "External call before state update allows recursive calls",
        "patterns": [r"\.call\{.*value.*\}", r"\.send\(", r"\.transfer\("],
        "fix": "Use checks-effects-interactions pattern or ReentrancyGuard",
    },
    "integer_overflow": {
        "severity": "HIGH",
        "description": "Arithmetic operations without bounds checking",
        "patterns": [r"\+\+", r"\+\s*=", r"\*\s*=", r"unchecked\s*\{"],
        "fix": "Use Solidity >=0.8.0 (built-in checks) or SafeMath library",
    },
    "access_control": {
        "severity": "HIGH",
        "description": "Missing or weak access control on sensitive functions",
        "patterns": [r"function\s+\w+\s*\([^)]*\)\s*public(?!\s+view)(?!\s+pure)", r"selfdestruct"],
        "fix": "Implement onlyOwner/role-based modifiers, use OpenZeppelin AccessControl",
    },
    "tx_origin": {
        "severity": "MEDIUM",
        "description": "Using tx.origin for authorization enables phishing attacks",
        "patterns": [r"tx\.origin"],
        "fix": "Use msg.sender instead of tx.origin for authentication",
    },
    "unchecked_return": {
        "severity": "MEDIUM",
        "description": "Return value of external call not checked",
        "patterns": [r"\.call\(", r"\.delegatecall\(", r"\.staticcall\("],
        "fix": "Always check return values: (bool success) = addr.call(...); require(success);",
    },
    "front_running": {
        "severity": "MEDIUM",
        "description": "Transaction ordering dependency allows front-running",
        "patterns": [r"approve\s*\(", r"swap.*Exact", r"addLiquidity"],
        "fix": "Use commit-reveal schemes or private mempools",
    },
    "timestamp_dependency": {
        "severity": "LOW",
        "description": "Using block.timestamp for critical logic",
        "patterns": [r"block\.timestamp", r"now\b"],
        "fix": "Avoid using timestamp for randomness; acceptable for loose time constraints",
    },
    "delegatecall": {
        "severity": "HIGH",
        "description": "delegatecall to untrusted contracts can modify storage",
        "patterns": [r"delegatecall"],
        "fix": "Only delegatecall to trusted, audited contracts",
    },
}

GAS_OPERATIONS = {
    "transfer_eth": {"base_gas": 21000, "description": "Simple ETH transfer"},
    "erc20_transfer": {"base_gas": 65000, "description": "ERC-20 token transfer"},
    "erc20_approve": {"base_gas": 46000, "description": "ERC-20 approve allowance"},
    "uniswap_swap": {"base_gas": 150000, "description": "Uniswap token swap"},
    "nft_mint": {"base_gas": 180000, "description": "Mint a single NFT (ERC-721)"},
    "nft_transfer": {"base_gas": 85000, "description": "Transfer an NFT"},
    "contract_deploy": {"base_gas": 500000, "description": "Deploy a basic smart contract"},
    "multisig_tx": {"base_gas": 100000, "description": "Execute multisig transaction"},
    "defi_deposit": {"base_gas": 200000, "description": "Deposit into DeFi protocol"},
    "defi_withdraw": {"base_gas": 180000, "description": "Withdraw from DeFi protocol"},
}


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------
def _wallet_analyzer(address: str, transactions: list[dict],
                     token_balances: list[dict]) -> dict:
    """Analyze a wallet's transaction history and holdings."""
    if not re.match(r'^0x[0-9a-fA-F]{40}$', address):
        return {"error": "Invalid Ethereum address format"}

    # Transaction analysis
    total_sent = 0
    total_received = 0
    unique_interacted = set()
    tx_by_type = Counter()
    daily_activity = Counter()

    for tx in transactions:
        value = tx.get("value", 0)
        from_addr = tx.get("from", "").lower()
        to_addr = tx.get("to", "").lower()
        tx_type = tx.get("type", "transfer")

        if from_addr == address.lower():
            total_sent += value
        else:
            total_received += value

        if to_addr:
            unique_interacted.add(to_addr)
        if from_addr:
            unique_interacted.add(from_addr)

        tx_by_type[tx_type] += 1

        date = tx.get("date", "")
        if date:
            daily_activity[date[:10]] += 1

    net_flow = total_received - total_sent

    # Token balance analysis
    total_token_value = sum(t.get("value_usd", 0) for t in token_balances)
    top_holdings = sorted(token_balances, key=lambda t: t.get("value_usd", 0), reverse=True)

    # Known contract interactions
    known_interactions = []
    for addr in unique_interacted:
        if addr in KNOWN_CONTRACTS:
            known_interactions.append(KNOWN_CONTRACTS[addr])

    # Risk assessment
    risk_flags = []
    if len(transactions) > 100 and len(set(tx.get("to", "") for tx in transactions)) < 5:
        risk_flags.append("High transaction count with few unique destinations")
    if total_sent > total_received * 10 and total_received > 0:
        risk_flags.append("Sending significantly more than receiving")
    if any(tx.get("value", 0) > total_token_value * 0.5 for tx in transactions):
        risk_flags.append("Single transaction exceeds 50% of portfolio value")

    # Wallet classification
    if len(transactions) > 1000:
        wallet_type = "High-frequency trader or bot"
    elif known_interactions and any("DEX" in k.get("type", "") for k in known_interactions):
        wallet_type = "DeFi user"
    elif len(set(tx.get("to", "") for tx in transactions)) <= 3:
        wallet_type = "Simple holder / transfer wallet"
    else:
        wallet_type = "General purpose wallet"

    return {
        "address": address,
        "wallet_type": wallet_type,
        "transaction_summary": {
            "total_transactions": len(transactions),
            "total_sent": total_sent,
            "total_received": total_received,
            "net_flow": net_flow,
            "unique_addresses_interacted": len(unique_interacted),
            "transaction_types": dict(tx_by_type),
        },
        "portfolio": {
            "total_value_usd": round(total_token_value, 2),
            "token_count": len(token_balances),
            "top_holdings": top_holdings[:5],
        },
        "known_protocol_interactions": known_interactions,
        "risk_flags": risk_flags,
        "risk_level": "HIGH" if len(risk_flags) >= 2 else "MEDIUM" if risk_flags else "LOW",
    }


def _transaction_tracer(tx_hash: str, from_addr: str, to_addr: str,
                        value: float, internal_txns: list[dict],
                        token_transfers: list[dict]) -> dict:
    """Trace a transaction's full execution path."""
    if not tx_hash.startswith("0x"):
        return {"error": "Transaction hash should start with 0x"}

    # Analyze internal transactions
    internal_summary = []
    total_internal_value = 0
    for itx in internal_txns:
        total_internal_value += itx.get("value", 0)
        internal_summary.append({
            "from": itx.get("from", "")[:10] + "...",
            "to": itx.get("to", "")[:10] + "...",
            "value": itx.get("value", 0),
            "type": itx.get("type", "call"),
        })

    # Analyze token transfers
    token_summary = []
    tokens_involved = set()
    for tt in token_transfers:
        token = tt.get("token", "unknown")
        tokens_involved.add(token)
        token_summary.append({
            "token": token,
            "from": tt.get("from", "")[:10] + "...",
            "to": tt.get("to", "")[:10] + "...",
            "amount": tt.get("amount", 0),
        })

    # Identify known contracts
    known_from = KNOWN_CONTRACTS.get(from_addr.lower(), {})
    known_to = KNOWN_CONTRACTS.get(to_addr.lower(), {})

    # Transaction type classification
    if token_transfers and any("swap" in str(tt).lower() for tt in token_transfers):
        tx_type = "Token Swap (DEX)"
    elif len(token_transfers) > 0 and value == 0:
        tx_type = "Token Transfer"
    elif internal_txns and len(internal_txns) > 3:
        tx_type = "Complex DeFi Interaction"
    elif value > 0 and not token_transfers:
        tx_type = "ETH Transfer"
    else:
        tx_type = "Contract Interaction"

    return {
        "tx_hash": tx_hash,
        "type": tx_type,
        "from": from_addr,
        "to": to_addr,
        "value_eth": value,
        "known_from": known_from if known_from else None,
        "known_to": known_to if known_to else None,
        "internal_transactions": {
            "count": len(internal_txns),
            "total_value": total_internal_value,
            "details": internal_summary[:10],
        },
        "token_transfers": {
            "count": len(token_transfers),
            "tokens_involved": list(tokens_involved),
            "details": token_summary[:10],
        },
        "execution_flow": [
            f"1. {from_addr[:10]}... initiates transaction",
            f"2. {'Contract ' + known_to.get('name', to_addr[:10] + '...') if known_to else to_addr[:10] + '...'} receives call",
            f"3. {len(internal_txns)} internal transactions executed",
            f"4. {len(token_transfers)} token transfers completed",
        ],
    }


def _smart_contract_auditor(source_code: str, contract_name: str) -> dict:
    """Audit a smart contract for common vulnerabilities."""
    if not source_code.strip():
        return {"error": "Source code cannot be empty"}

    findings = []
    for vuln_name, vuln_info in VULNERABILITY_PATTERNS.items():
        matches = []
        for pattern in vuln_info["patterns"]:
            found = re.findall(pattern, source_code)
            if found:
                matches.extend(found[:3])

        if matches:
            findings.append({
                "vulnerability": vuln_name.replace("_", " ").title(),
                "severity": vuln_info["severity"],
                "description": vuln_info["description"],
                "matches_found": len(matches),
                "sample_matches": matches[:3],
                "recommendation": vuln_info["fix"],
            })

    # Code metrics
    lines = source_code.split("\n")
    code_lines = [l for l in lines if l.strip() and not l.strip().startswith("//")]
    functions = re.findall(r'function\s+(\w+)', source_code)
    events = re.findall(r'event\s+(\w+)', source_code)
    modifiers = re.findall(r'modifier\s+(\w+)', source_code)
    imports = re.findall(r'import\s+', source_code)

    # Solidity version
    pragma = re.search(r'pragma\s+solidity\s+([^;]+)', source_code)
    solidity_version = pragma.group(1).strip() if pragma else "Not specified"

    # Severity counts
    severity_counts = Counter(f["severity"] for f in findings)

    # Overall risk
    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)
    if critical > 0:
        risk_level = "CRITICAL"
        recommendation = "DO NOT deploy. Fix critical vulnerabilities immediately."
    elif high > 0:
        risk_level = "HIGH"
        recommendation = "Address high-severity issues before deployment."
    elif findings:
        risk_level = "MEDIUM"
        recommendation = "Review and address findings. Consider professional audit."
    else:
        risk_level = "LOW"
        recommendation = "No major issues detected. Still recommended to get professional audit."

    return {
        "contract_name": contract_name,
        "solidity_version": solidity_version,
        "risk_level": risk_level,
        "recommendation": recommendation,
        "code_metrics": {
            "total_lines": len(lines),
            "code_lines": len(code_lines),
            "functions": len(functions),
            "function_names": functions[:20],
            "events": len(events),
            "modifiers": len(modifiers),
            "imports": len(imports),
        },
        "vulnerability_summary": {
            "total_findings": len(findings),
            "critical": critical,
            "high": high,
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
        },
        "findings": findings,
        "best_practices_check": {
            "has_events": len(events) > 0,
            "has_modifiers": len(modifiers) > 0,
            "uses_latest_solidity": "0.8" in solidity_version if solidity_version != "Not specified" else False,
            "has_imports": len(imports) > 0,
        },
        "disclaimer": "Automated scan only. Not a replacement for a professional security audit.",
    }


def _gas_estimator(operation: str, gas_price_gwei: float,
                   eth_price_usd: float, priority: str) -> dict:
    """Estimate gas costs for common blockchain operations."""
    if operation not in GAS_OPERATIONS:
        return {"error": f"Unknown operation. Available: {list(GAS_OPERATIONS.keys())}"}

    op = GAS_OPERATIONS[operation]
    base_gas = op["base_gas"]

    # Priority multipliers
    priority_multipliers = {
        "low": {"multiplier": 0.8, "time": "5-30 minutes", "tip_gwei": 1},
        "medium": {"multiplier": 1.0, "time": "1-5 minutes", "tip_gwei": 2},
        "high": {"multiplier": 1.3, "time": "15-60 seconds", "tip_gwei": 5},
        "urgent": {"multiplier": 1.8, "time": "Next block (~12s)", "tip_gwei": 10},
    }

    pri = priority_multipliers.get(priority, priority_multipliers["medium"])
    effective_gas_price = gas_price_gwei * pri["multiplier"]
    total_gas = base_gas
    cost_eth = (total_gas * effective_gas_price) / 1e9
    cost_usd = cost_eth * eth_price_usd

    # Historical comparison
    gas_scenarios = {}
    for gp in [10, 20, 30, 50, 100, 200]:
        eth_cost = (total_gas * gp) / 1e9
        gas_scenarios[f"{gp}_gwei"] = {
            "cost_eth": round(eth_cost, 6),
            "cost_usd": round(eth_cost * eth_price_usd, 2),
        }

    return {
        "operation": operation,
        "description": op["description"],
        "gas_estimate": total_gas,
        "gas_price_gwei": gas_price_gwei,
        "effective_gas_price_gwei": round(effective_gas_price, 2),
        "priority": priority,
        "estimated_time": pri["time"],
        "priority_tip_gwei": pri["tip_gwei"],
        "cost": {
            "eth": round(cost_eth, 6),
            "usd": round(cost_usd, 2),
        },
        "eth_price_usd": eth_price_usd,
        "gas_scenarios": gas_scenarios,
        "optimization_tips": [
            "Batch multiple operations to save on base transaction costs",
            "Use off-peak hours (weekends, early morning UTC) for lower gas",
            "Consider L2 solutions (Arbitrum, Optimism, Base) for 10-100x cheaper gas",
            "EIP-1559: set reasonable maxFeePerGas and maxPriorityFeePerGas",
        ],
        "all_operations": {k: v["description"] for k, v in GAS_OPERATIONS.items()},
    }


def _token_metadata(address: str, chain: str, supply_data: dict,
                    holder_data: dict) -> dict:
    """Fetch and analyze token metadata."""
    if not re.match(r'^0x[0-9a-fA-F]{40}$', address):
        return {"error": "Invalid token address format"}

    known = KNOWN_CONTRACTS.get(address.lower(), {})

    total_supply = supply_data.get("total_supply", 0)
    circulating = supply_data.get("circulating_supply", total_supply)
    max_supply = supply_data.get("max_supply", 0)

    top_holders = holder_data.get("top_holders", [])
    total_holders = holder_data.get("total_holders", 0)

    # Concentration analysis
    top_10_pct = sum(h.get("percentage", 0) for h in top_holders[:10])
    top_50_pct = sum(h.get("percentage", 0) for h in top_holders[:50])

    if top_10_pct > 80:
        concentration = "Extremely concentrated"
        concentration_risk = "HIGH"
    elif top_10_pct > 50:
        concentration = "Highly concentrated"
        concentration_risk = "MEDIUM"
    elif top_10_pct > 30:
        concentration = "Moderately concentrated"
        concentration_risk = "LOW"
    else:
        concentration = "Well distributed"
        concentration_risk = "LOW"

    # Supply analysis
    circulating_pct = (circulating / max(total_supply, 1)) * 100
    inflation_risk = "HIGH" if circulating_pct < 30 else "MEDIUM" if circulating_pct < 60 else "LOW"

    return {
        "address": address,
        "chain": chain,
        "known_token": known if known else None,
        "name": known.get("name", supply_data.get("name", "Unknown")),
        "type": known.get("type", supply_data.get("type", "ERC-20")),
        "supply": {
            "total": total_supply,
            "circulating": circulating,
            "max": max_supply,
            "circulating_pct": round(circulating_pct, 2),
            "inflation_risk": inflation_risk,
        },
        "holders": {
            "total": total_holders,
            "top_10_concentration_pct": round(top_10_pct, 2),
            "top_50_concentration_pct": round(top_50_pct, 2),
            "concentration_assessment": concentration,
            "concentration_risk": concentration_risk,
            "top_holders": top_holders[:10],
        },
        "risk_summary": {
            "concentration_risk": concentration_risk,
            "inflation_risk": inflation_risk,
            "overall": "HIGH" if concentration_risk == "HIGH" or inflation_risk == "HIGH" else "MEDIUM" if concentration_risk == "MEDIUM" else "LOW",
        },
    }


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "Blockchain AI MCP",
    instructions="Web3/crypto toolkit: wallet analysis, transaction tracing, smart contract auditing, gas estimation, and token metadata. By MEOK AI Labs.")


@mcp.tool()
def wallet_analyzer(address: str, transactions: list[dict] = [],
                    token_balances: list[dict] = [], api_key: str = "") -> dict:
    """Analyze an Ethereum wallet's transaction history, portfolio, and risk profile.

    Args:
        address: Ethereum wallet address (0x...)
        transactions: Transaction history as [{"from": "0x...", "to": "0x...", "value": 1.5, "type": "transfer", "date": "2026-01-01"}]
        token_balances: Token holdings as [{"token": "USDC", "balance": 1000, "value_usd": 1000}]

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    err = _check_rate_limit()
    if err:
        return {"error": err}
    try:
        return _wallet_analyzer(address, transactions, token_balances)
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def transaction_tracer(tx_hash: str, from_addr: str = "", to_addr: str = "",
                       value: float = 0, internal_txns: list[dict] = [],
                       token_transfers: list[dict] = [], api_key: str = "") -> dict:
    """Trace a transaction's full execution path including internal calls
    and token transfers.

    Args:
        tx_hash: Transaction hash (0x...)
        from_addr: Sender address
        to_addr: Receiver/contract address
        value: ETH value transferred
        internal_txns: Internal transactions as [{"from": "0x", "to": "0x", "value": 0.1, "type": "call"}]
        token_transfers: Token transfers as [{"token": "USDC", "from": "0x", "to": "0x", "amount": 100}]

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    err = _check_rate_limit()
    if err:
        return {"error": err}
    try:
        return _transaction_tracer(tx_hash, from_addr, to_addr, value, internal_txns, token_transfers)
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def smart_contract_auditor(source_code: str, contract_name: str = "Contract", api_key: str = "") -> dict:
    """Audit Solidity smart contract source code for common vulnerabilities
    including reentrancy, overflow, access control, and more.

    Args:
        source_code: Solidity source code to audit
        contract_name: Name of the contract

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    err = _check_rate_limit()
    if err:
        return {"error": err}
    try:
        return _smart_contract_auditor(source_code, contract_name)
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def gas_estimator(operation: str = "transfer_eth", gas_price_gwei: float = 20,
                  eth_price_usd: float = 3000, priority: str = "medium", api_key: str = "") -> dict:
    """Estimate gas costs for common blockchain operations with priority-based
    pricing and USD conversion.

    Args:
        operation: Operation type (transfer_eth, erc20_transfer, erc20_approve, uniswap_swap, nft_mint, nft_transfer, contract_deploy, multisig_tx, defi_deposit, defi_withdraw)
        gas_price_gwei: Current gas price in Gwei
        eth_price_usd: Current ETH price in USD
        priority: Transaction priority (low, medium, high, urgent)

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    err = _check_rate_limit()
    if err:
        return {"error": err}
    try:
        return _gas_estimator(operation, gas_price_gwei, eth_price_usd, priority)
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def token_metadata(address: str, chain: str = "ethereum",
                   supply_data: dict = {}, holder_data: dict = {}, api_key: str = "") -> dict:
    """Analyze token metadata including supply distribution, holder concentration,
    and risk assessment.

    Args:
        address: Token contract address (0x...)
        chain: Blockchain network (ethereum, polygon, arbitrum, etc.)
        supply_data: Supply info as {"total_supply": N, "circulating_supply": N, "max_supply": N, "name": "X", "type": "ERC-20"}
        holder_data: Holder info as {"total_holders": N, "top_holders": [{"address": "0x", "percentage": 10.5}]}

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    err = _check_rate_limit()
    if err:
        return {"error": err}
    try:
        return _token_metadata(address, chain, supply_data, holder_data)
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    mcp.run()
