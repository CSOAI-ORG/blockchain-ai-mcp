# Blockchain AI MCP Server
**By MEOK AI Labs** | [meok.ai](https://meok.ai)

Web3/crypto toolkit: wallet analysis, transaction tracing, smart contract auditing, gas estimation, and token metadata.

## Tools

| Tool | Description |
|------|-------------|
| `wallet_analyzer` | Analyze wallet transaction history, portfolio, and risk profile |
| `transaction_tracer` | Trace transaction execution path with internal calls |
| `smart_contract_auditor` | Audit Solidity contracts for common vulnerabilities |
| `gas_estimator` | Estimate gas costs for common blockchain operations |
| `token_metadata` | Analyze token supply distribution and holder concentration |

## Installation

```bash
pip install mcp
```

## Usage

### Run the server

```bash
python server.py
```

### Claude Desktop config

```json
{
  "mcpServers": {
    "blockchain": {
      "command": "python",
      "args": ["/path/to/blockchain-ai-mcp/server.py"]
    }
  }
}
```

## Pricing

| Tier | Limit | Price |
|------|-------|-------|
| Free | 30 calls/day | $0 |
| Pro | Unlimited + premium features | $9/mo |
| Enterprise | Custom + SLA + support | Contact us |

## License

MIT
