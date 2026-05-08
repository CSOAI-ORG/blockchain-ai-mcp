<div align="center">

# Blockchain Ai MCP

**MCP server for blockchain ai mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-blockchain-ai-mcp)](https://pypi.org/project/meok-blockchain-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Blockchain Ai MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `wallet_analyzer` | Analyze an Ethereum wallet's transaction history, portfolio, and risk profile. |
| `transaction_tracer` | Trace a transaction's full execution path including internal calls |
| `smart_contract_auditor` | Audit Solidity smart contract source code for common vulnerabilities |
| `gas_estimator` | Estimate gas costs for common blockchain operations with priority-based |
| `token_metadata` | Analyze token metadata including supply distribution, holder concentration, |

## Installation

```bash
pip install meok-blockchain-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "blockchain-ai-mcp": {
      "command": "python",
      "args": ["-m", "meok_blockchain_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 5 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
