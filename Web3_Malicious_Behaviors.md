# Web3 & Blockchain Malicious Behaviors Catalog

## Overview

This catalog documents **behavioral patterns and attack methodologies** that are either unique to blockchain environments or significantly adapted for decentralized systems. Unlike static IOCs, these represent **dynamic patterns of malicious activity** that can be detected through behavioral analysis, transaction patterns, and ecosystem-wide coordination signals.

**Key Distinction**: While IOCs identify *what* is malicious (addresses, contracts, domains), this catalog identifies *how* malicious actors operate in Web3 environments.

---

## Table of Contents

1. [Financial Exploitation Behaviors](#financial-exploitation-behaviors)
2. [Smart Contract Attack Patterns](#smart-contract-attack-patterns)
3. [Ecosystem Manipulation](#ecosystem-manipulation)
4. [Social Engineering in DeFi](#social-engineering-in-defi)
5. [Privacy Abuse Patterns](#privacy-abuse-patterns)
6. [NFT and Gaming Exploitation](#nft-and-gaming-exploitation)
7. [Infrastructure Attack Behaviors](#infrastructure-attack-behaviors)
8. [Cross-Chain Attack Patterns](#cross-chain-attack-patterns)
9. [Detection Methodologies](#detection-methodologies)
10. [Behavioral Risk Scoring](#behavioral-risk-scoring)

---

## Financial Exploitation Behaviors

### 1. Rug Pull Patterns

**Definition**: Coordinated exit scams where project creators drain liquidity or funds from their protocol.

**Behavioral Indicators**:
- **Liquidity Removal Patterns**:
  - Sudden, large LP token withdrawals by team addresses
  - Coordinated withdrawals across multiple pools simultaneously
  - Removing liquidity during high trading volume periods
  - Using multiple addresses to avoid detection limits

- **Token Distribution Manipulation**:
  - Team addresses accumulating tokens before announcement
  - Coordinated selling by "insider" addresses
  - Distribution of tokens to new addresses just before dumps
  - Price impact minimization through gradual distributions

- **Communication Behavior**:
  - Social media accounts going silent before/during rug
  - Deletion of official channels (Discord, Telegram)
  - Transfer of domain ownership or letting domains expire
  - Team members leaving or accounts being deactivated

**Detection Timeline**: 
- **Pre-rug (1-7 days)**: Unusual team wallet activity, social signals
- **Active rug (minutes-hours)**: Rapid liquidity drainage
- **Post-rug (immediate)**: Communication blackout, website down

**Case Study Pattern**: 
```
Day -3: Team accumulates 15% more tokens via secondary addresses
Day -1: Social media activity decreases by 80%
Day 0, Hour 0: First large LP withdrawal (25% of liquidity)
Day 0, Hour 0.5: Remaining liquidity pulled via 6 different addresses
Day 0, Hour 1: Official Telegram deleted, website returns 404
```

### 2. Pump and Dump Coordination

**Definition**: Coordinated price manipulation through synchronized buying followed by coordinated selling.

**Behavioral Indicators**:
- **Coordination Signals**:
  - Multiple addresses with similar funding sources buying simultaneously
  - Addresses created within short time windows acting in concert
  - Similar transaction patterns (amounts, timing, gas prices)
  - Coordinated social media promotion campaigns

- **Artificial Volume Generation**:
  - High frequency trading between related addresses
  - Large buy orders immediately followed by sell orders
  - Volume spikes that don't correspond to organic interest
  - Wash trading patterns to create false liquidity appearance

- **Distribution Patterns**:
  - Coordinated selling by multiple addresses at predetermined price levels
  - Using different DEXs to minimize price impact detection
  - Staggered selling over time to appear organic
  - Immediate transfers to mixers or exchanges post-dump

**Technical Detection**:
```python
# Pseudocode for pump coordination detection
def detect_pump_coordination(token_address, time_window):
    buys = get_buy_transactions(token_address, time_window)
    
    # Check for coordination signals
    coordination_score = 0
    
    # Similar funding patterns
    funding_sources = analyze_funding_sources(buys)
    if has_common_funding_source(funding_sources):
        coordination_score += 30
    
    # Timing correlation  
    timing_correlation = calculate_timing_correlation(buys)
    if timing_correlation > 0.8:
        coordination_score += 25
        
    # Similar transaction characteristics
    tx_similarity = analyze_transaction_similarity(buys)
    if tx_similarity > 0.7:
        coordination_score += 20
        
    return coordination_score >= 50  # Threshold for coordination
```

### 3. Flash Loan Attack Patterns

**Definition**: Using uncollateralized loans to manipulate DeFi protocols within a single transaction.

**Behavioral Indicators**:
- **Attack Transaction Structure**:
  - Large flash loan initiation (often multiple millions)
  - Complex sequence of swaps across multiple DEXs
  - Price oracle manipulation attempts
  - Liquidation of positions based on manipulated prices
  - Loan repayment in same transaction

- **Preparation Patterns**:
  - Contract deployment with complex logic shortly before attack
  - Testing small amounts on similar protocols
  - Monitoring of target protocol's liquidity and oracle updates
  - Gas price optimization for atomic execution

- **Multi-Protocol Exploitation**:
  - Simultaneous interaction with 5+ DeFi protocols
  - Arbitrage across multiple DEXs within single transaction
  - Oracle price manipulation across different price feeds
  - Liquidation of multiple positions simultaneously

**Common Attack Flow**:
```
1. Deploy attack contract or use existing one
2. Flash loan large amount (e.g., 10M USDC)
3. Use loan to manipulate price oracle via large swaps
4. Liquidate positions based on manipulated oracle price
5. Perform reverse swaps to restore some price stability
6. Repay flash loan + fees
7. Keep profit from liquidations
```

### 4. MEV (Maximal Extractable Value) Abuse

**Definition**: Exploiting transaction ordering and block production to extract value from other users.

**Behavioral Indicators**:
- **Front-running Patterns**:
  - Consistently placing transactions immediately before large trades
  - Using higher gas prices to ensure transaction ordering
  - Copying transaction parameters but with modified amounts
  - Automated responses to mempool activity

- **Sandwich Attacks**:
  - Transaction A: Buy before victim's transaction
  - Victim's transaction executes at worse price
  - Transaction B: Sell immediately after for profit
  - All transactions appear in consecutive blocks

- **Liquidation Bot Behavior**:
  - Monitoring health factors of lending positions continuously
  - Immediately submitting liquidation transactions when positions become unhealthy
  - Using gas optimization to win liquidation auctions
  - Coordinating across multiple lending protocols

**Detection Signals**:
```
MEV Bot Identification:
- Transaction success rate > 95%
- Average gas price 20%+ above network average
- Transactions clustered around large trades (±1-2 blocks)
- Consistent profit extraction from transaction ordering
- Interaction with MEV relay services
```

---

## Smart Contract Attack Patterns

### 1. Reentrancy Attack Behavior

**Definition**: Exploiting callbacks to drain funds before state updates are complete.

**Behavioral Indicators**:
- **Attack Contract Patterns**:
  - Contract with fallback function that calls back to target
  - Testing phase with small amounts before main attack
  - Single transaction with recursive call patterns
  - Immediate token transfers post-exploitation

- **Preparation Behavior**:
  - Deployment of attack contract shortly before exploitation
  - Analysis transactions to understand target contract logic
  - Gas limit testing to optimize attack parameters
  - Multiple small test transactions to avoid detection

**Classic Attack Flow**:
```solidity
// Reentrancy attack pattern
contract ReentrancyAttacker {
    function attack(address target) external {
        // 1. Call withdraw function
        target.call(abi.encodeWithSignature("withdraw(uint256)", amount));
    }
    
    // 2. Fallback function called during withdrawal
    fallback() external payable {
        if (target.balance >= amount) {
            // 3. Call withdraw again before state update
            target.call(abi.encodeWithSignature("withdraw(uint256)", amount));
        }
    }
}
```

### 2. Oracle Manipulation Attacks

**Definition**: Manipulating price oracles to exploit lending protocols or other price-dependent systems.

**Behavioral Indicators**:
- **Price Impact Patterns**:
  - Large swaps creating temporary price deviations
  - Immediate liquidations following price manipulation
  - Quick reversal trades to restore original prices
  - Coordination across multiple DEXs simultaneously

- **Oracle Exploitation Sequence**:
  - Monitor oracle update mechanisms and delays
  - Execute large trades right after oracle updates
  - Exploit the delay before next oracle price update
  - Liquidate positions based on manipulated price

**Multi-DEX Oracle Manipulation**:
```
Step 1: Identify target lending protocol using DEX-based oracles
Step 2: Accumulate large position in target token across multiple DEXs
Step 3: Execute coordinated large trades to move price significantly
Step 4: Immediately interact with lending protocol using manipulated price
Step 5: Reverse trades before oracle updates to minimize loss
```

### 3. Governance Attack Patterns

**Definition**: Exploiting governance mechanisms to gain unauthorized control or extract value.

**Behavioral Indicators**:
- **Voting Power Accumulation**:
  - Rapid accumulation of governance tokens before proposals
  - Borrowing governance tokens from lending protocols
  - Creating multiple addresses to distribute voting power
  - Timing token purchases with proposal submissions

- **Proposal Manipulation**:
  - Submitting proposals that appear benign but contain malicious code
  - Using complex proxy patterns to hide true proposal effects
  - Timing proposals during low community engagement periods
  - Creating decoy proposals to distract from malicious ones

- **Flash Governance Attacks**:
  - Using flash loans to temporarily acquire voting power
  - Executing governance decisions within single transaction
  - Immediately selling tokens after governance execution
  - Coordinating across multiple governance protocols

**Attack Timeline**:
```
Week 1-2: Accumulate governance tokens gradually
Week 3: Submit seemingly innocent proposal
Week 4: Rally support through social engineering
Week 5: Execute governance change
Week 5 (immediate): Execute malicious action enabled by governance change
```

---

## Ecosystem Manipulation

### 1. Sybil Attack Patterns

**Definition**: Creating multiple fake identities to gain disproportionate influence in decentralized systems.

**Behavioral Indicators**:
- **Address Creation Patterns**:
  - Multiple addresses funded from single source
  - Similar transaction patterns across multiple addresses
  - Coordinated timing of activities across address clusters
  - Similar gas price preferences and transaction structures

- **Governance Sybil Indicators**:
  - Multiple addresses with minimum governance token requirements
  - Coordinated voting patterns across addresses
  - Similar delegation patterns or voting timing
  - Addresses activated only during governance periods

- **DeFi Farming Sybil Patterns**:
  - Multiple addresses participating in same yield farming programs
  - Distribution of funds to stay below detection thresholds
  - Coordinated claiming of rewards across addresses
  - Similar interaction patterns with DeFi protocols

**Detection Algorithm**:
```python
def detect_sybil_cluster(addresses):
    sybil_score = 0
    
    # Check funding patterns
    common_funders = find_common_funding_sources(addresses)
    if len(common_funders) > 0:
        sybil_score += 40
    
    # Check behavioral similarity
    behavior_similarity = calculate_behavior_similarity(addresses)
    sybil_score += behavior_similarity * 30
    
    # Check timing coordination
    timing_correlation = analyze_timing_patterns(addresses)
    sybil_score += timing_correlation * 20
    
    # Check gas price patterns
    gas_similarity = analyze_gas_patterns(addresses)
    sybil_score += gas_similarity * 10
    
    return sybil_score >= 70  # Sybil cluster threshold
```

### 2. Network Spam and DoS Patterns

**Definition**: Overwhelming blockchain networks or specific protocols to cause service degradation.

**Behavioral Indicators**:
- **Transaction Spam Patterns**:
  - High volume of low-value transactions
  - Transactions with minimal computational requirements
  - Systematic targeting of specific smart contracts
  - Coordinated spam from multiple addresses

- **Gas Price Manipulation**:
  - Sudden spikes in gas prices during important events
  - Consistent high gas price transactions to clog network
  - Targeting specific time periods (governance votes, token launches)
  - Using bots to automatically outbid legitimate transactions

- **MEV Bot Wars**:
  - Multiple bots competing with increasingly high gas prices
  - Rapid escalation of transaction fees during opportunities
  - Failed transactions due to gas price competition
  - Network congestion during high MEV opportunities

### 3. Validator Misbehavior (Proof-of-Stake)

**Definition**: Malicious or negligent behavior by network validators.

**Behavioral Indicators**:
- **Slashing Events**:
  - Validators signing conflicting blocks
  - Validators going offline during critical periods
  - Coordinated validator failures suggesting collusion
  - Pattern of minor infractions leading to major slashing

- **Censorship Patterns**:
  - Consistent exclusion of specific transactions
  - Longer than normal transaction confirmation times
  - Selective processing based on transaction content
  - Coordinated transaction censorship across validators

- **MEV Extraction Abuse**:
  - Validators extracting excessive MEV from users
  - Coordinated transaction reordering for profit
  - Preferential treatment for specific transaction types
  - Block building patterns that maximize validator profit over user experience

---

## Social Engineering in DeFi

### 1. Fake Protocol Launch Patterns

**Definition**: Creating sophisticated fake DeFi protocols to steal user funds.

**Behavioral Indicators**:
- **Development Simulation**:
  - Fake GitHub repositories with committed activity
  - Purchased code reviews and audit reports
  - Professional-looking documentation and whitepapers
  - Simulated community building and social media presence

- **Launch Coordination**:
  - Coordinated social media marketing campaigns
  - Fake influencer endorsements and partnerships
  - Professional website and branding materials
  - Gradual rollout to build credibility before major launch

- **Trust Building Behavior**:
  - Small, successful operations to build reputation
  - Paying early users to create positive testimonials
  - Fake team members with generated profiles
  - Purchased social media followers and engagement

### 2. Community Takeover Attempts

**Definition**: Systematically infiltrating and taking control of legitimate project communities.

**Behavioral Indicators**:
- **Infiltration Patterns**:
  - Multiple new accounts joining community simultaneously
  - Accounts with purchased or artificial engagement history
  - Coordinated messaging across multiple platforms
  - Gradual escalation from helpful to controlling behavior

- **Authority Usurpation**:
  - Impersonating team members or moderators
  - Creating confusion about official communication channels
  - Spreading misinformation about project development
  - Attempting to redirect community to controlled channels

- **Resource Theft**:
  - Attempting to gain control of official social media accounts
  - Trying to access project treasury or multisig wallets
  - Stealing community member contact information
  - Redirecting donations or investments to controlled addresses

---

## Privacy Abuse Patterns

### 1. DeFi Money Laundering Behaviors

**Definition**: Using decentralized finance protocols to obscure the origin of illicit funds.

**Behavioral Indicators**:
- **Layering Through DeFi**:
  - Multiple swaps across different DEXs
  - Breaking large amounts into smaller transactions
  - Using yield farming to create legitimate transaction history
  - Depositing and withdrawing from lending protocols

- **Cross-Protocol Obfuscation**:
  - Moving funds through multiple DeFi protocols sequentially
  - Using privacy-focused protocols (mixers, privacy coins)
  - Creating complex transaction chains across multiple addresses
  - Timing delays between transactions to avoid pattern detection

- **Synthetic Asset Manipulation**:
  - Converting to synthetic assets or derivatives
  - Using lending protocols to create borrowing/repayment cycles
  - Utilizing prediction markets to obfuscate fund movements
  - Creating and redeeming synthetic tokens across platforms

**Laundering Pattern Example**:
```
Original Funds (Stolen ETH) →
├── Swap 30% to USDC on Uniswap
├── Swap 30% to DAI on SushiSwap  
├── Deposit 40% in Aave lending pool
└── Wait 24 hours

Second Layer →
├── Withdraw from Aave, swap to WBTC
├── Convert USDC/DAI to various altcoins
├── Use Tornado Cash for ETH mixing
└── Bridge to different chains

Final Layer →
├── Recombine on different chain
├── Use cross-chain DEX for final conversion
├── Deposit to centralized exchange
└── Convert to fiat or clean crypto
```

### 2. Cross-Chain Laundering Networks

**Definition**: Using multiple blockchain networks to obscure fund trails.

**Behavioral Indicators**:
- **Bridge Pattern Abuse**:
  - Rapid movement between chains using different bridge protocols
  - Breaking large amounts across multiple bridge transactions
  - Using different addresses on each chain
  - Timing delays to avoid cross-chain correlation

- **Chain-Specific Strategies**:
  - Using privacy-focused chains (Monero, Zcash features)
  - Exploiting chains with lower KYC/AML compliance
  - Utilizing chains with different regulatory environments
  - Taking advantage of chain-specific mixing or privacy protocols

### 3. Mixer and Tumbler Usage Patterns

**Definition**: Systematic use of privacy protocols to break transaction linkability.

**Behavioral Indicators**:
- **Tornado Cash Patterns**:
  - Standard denomination deposits (0.1, 1, 10, 100 ETH)
  - Timing delays between deposit and withdrawal
  - Using different addresses for deposits and withdrawals
  - Multiple deposit/withdrawal cycles to increase anonymity

- **Mixer Network Usage**:
  - Using multiple mixing services for same funds
  - Splitting funds across different privacy protocols
  - Coordinated mixing with other addresses (mixing pools)
  - Using decentralized mixing protocols vs centralized services

---

## NFT and Gaming Exploitation

### 1. NFT Wash Trading Networks

**Definition**: Creating artificial trading volume and price floors through self-trading.

**Behavioral Indicators**:
- **Self-Trading Patterns**:
  - Trading between addresses with common funding sources
  - Circular trading patterns (A→B→C→A)
  - Trading at progressively higher prices to create price history
  - Immediate re-listing after purchases

- **Market Manipulation**:
  - Creating false scarcity through coordinated buying
  - Bidding wars between controlled addresses
  - Artificial floor price establishment through coordinated listings
  - Fake volume generation during key market events

- **Platform Gaming**:
  - Exploiting marketplace algorithms that reward volume
  - Gaming trending/featured listing algorithms
  - Manipulating rarity rankings through wash trading
  - Creating artificial social proof through fake sales

### 2. Gaming Economy Exploits

**Definition**: Exploiting blockchain-based games to unfairly extract value or gain advantages.

**Behavioral Indicators**:
- **Bot Farm Operations**:
  - Multiple game accounts with similar play patterns
  - Automated completion of game tasks or missions
  - Coordinated resource farming across multiple accounts
  - Identical progression patterns across accounts

- **Asset Duplication Exploits**:
  - Exploiting smart contract bugs to duplicate in-game assets
  - Using flash loans or reentrancy to create multiple claims
  - Exploiting bridge contracts to duplicate cross-chain assets
  - Taking advantage of timing issues in asset transfers

- **Economic Manipulation**:
  - Cornering markets for specific in-game resources
  - Manipulating in-game token prices through coordinated trading
  - Exploiting governance mechanisms to change game economics
  - Using multi-account strategies to dominate leaderboards

---

## Infrastructure Attack Behaviors

### 1. Frontend Hijacking Patterns

**Definition**: Compromising DApp frontends to steal user funds or data.

**Behavioral Indicators**:
- **DNS Poisoning**:
  - Redirecting legitimate domain names to malicious servers
  - Using similar domain names to capture misdirected traffic
  - Compromising domain registrar accounts to change DNS records
  - Using subdomain takeover techniques

- **CDN Compromise**:
  - Injecting malicious code into content delivery networks
  - Compromising third-party scripts loaded by DApps
  - Using supply chain attacks on common Web3 libraries
  - Exploiting vulnerable dependencies in frontend code

- **Wallet Integration Attacks**:
  - Modifying wallet connection interfaces to steal private keys
  - Creating fake transaction approval requests
  - Intercepting transaction data before signing
  - Injecting malicious contract addresses into transaction requests

### 2. RPC Endpoint Abuse

**Definition**: Exploiting or overwhelming blockchain RPC endpoints.

**Behavioral Indicators**:
- **Endpoint Overload**:
  - High volume of requests from single sources
  - Requests designed to consume maximum computational resources
  - Coordinated attacks across multiple endpoints simultaneously
  - Targeting specific expensive RPC methods repeatedly

- **Data Extraction**:
  - Systematic downloading of entire blockchain state
  - Automated analysis of mempool data for MEV opportunities
  - Large-scale address and transaction analysis
  - Historical data mining for pattern recognition

### 3. Wallet Drainer Campaigns

**Definition**: Coordinated campaigns to steal funds from cryptocurrency wallets.

**Behavioral Indicators**:
- **Social Engineering Infrastructure**:
  - Networks of fake social media accounts
  - Coordinated promotion of malicious links
  - Fake giveaway and airdrop campaigns
  - Impersonation of legitimate projects and influencers

- **Technical Infrastructure**:
  - Deployment of wallet drainer smart contracts
  - Creation of phishing websites that mimic legitimate DApps
  - Development of malicious browser extensions
  - Creation of fake mobile wallet applications

- **Campaign Coordination**:
  - Simultaneous launch across multiple social platforms
  - Coordination with influencer impersonation accounts
  - Timing campaigns with major market events or announcements
  - Using trending topics to increase visibility

---

## Cross-Chain Attack Patterns

### 1. Bridge Exploitation Behaviors

**Definition**: Attacking cross-chain bridge protocols to steal or manipulate assets.

**Behavioral Indicators**:
- **Bridge Mechanism Abuse**:
  - Exploiting validation mechanisms for cross-chain transfers
  - Double-spending attacks across different chains
  - Exploiting time delays in cross-chain confirmations
  - Manipulating oracle systems that verify cross-chain states

- **Multi-Chain Coordination**:
  - Coordinated attacks across multiple bridge protocols simultaneously
  - Using different attack vectors on each chain in the bridge
  - Exploiting differences in consensus mechanisms between chains
  - Timing attacks that exploit block time differences

### 2. Cross-Chain Arbitrage Manipulation

**Definition**: Exploiting price differences across chains through manipulation rather than legitimate arbitrage.

**Behavioral Indicators**:
- **Artificial Price Creation**:
  - Creating artificial price differences through large trades
  - Manipulating low-liquidity markets on smaller chains
  - Using flash loans to temporarily create arbitrage opportunities
  - Coordinating across multiple DEXs on different chains

- **Bridge Timing Exploitation**:
  - Exploiting the time delay in cross-chain asset transfers
  - Front-running cross-chain arbitrage opportunities
  - Using knowledge of pending cross-chain transactions
  - Manipulating gas prices to delay competitor transactions

---

## Detection Methodologies

### Behavioral Analysis Framework

#### 1. Transaction Pattern Analysis
```python
class BehaviorDetector:
    def analyze_transaction_patterns(self, address, time_window):
        patterns = {
            'frequency_anomalies': self.detect_frequency_changes(address, time_window),
            'amount_patterns': self.analyze_transaction_amounts(address),
            'timing_patterns': self.detect_timing_coordination(address),
            'counterparty_analysis': self.analyze_interaction_patterns(address),
            'gas_behavior': self.analyze_gas_patterns(address)
        }
        return self.calculate_behavior_score(patterns)
    
    def detect_coordination_clusters(self, addresses):
        # Detect groups of addresses acting in coordination
        coordination_metrics = {
            'funding_correlation': self.analyze_funding_sources(addresses),
            'timing_correlation': self.calculate_timing_correlation(addresses),
            'behavior_similarity': self.compare_transaction_behaviors(addresses),
            'interaction_patterns': self.analyze_cross_interactions(addresses)
        }
        return self.identify_clusters(coordination_metrics)
```

#### 2. Multi-Protocol Interaction Analysis
```python
def analyze_defi_behavior(address, protocols):
    behavior_flags = []
    
    # Flash loan pattern detection
    if self.has_flash_loan_patterns(address):
        behavior_flags.append('FLASH_LOAN_ABUSE')
    
    # Cross-protocol exploitation
    if self.detect_cross_protocol_exploitation(address, protocols):
        behavior_flags.append('CROSS_PROTOCOL_ATTACK')
    
    # MEV extraction patterns
    if self.detect_mev_behavior(address):
        behavior_flags.append('MEV_ABUSE')
    
    # Governance manipulation
    if self.detect_governance_manipulation(address):
        behavior_flags.append('GOVERNANCE_ATTACK')
        
    return behavior_flags
```

#### 3. Social Signal Integration
```python
def integrate_social_signals(address, social_data):
    social_risk_factors = {
        'associated_projects': self.analyze_project_associations(address, social_data),
        'community_reports': self.aggregate_community_reports(address),
        'social_media_correlation': self.correlate_social_activity(address, social_data),
        'influencer_warnings': self.check_influencer_flags(address)
    }
    return self.calculate_social_risk_score(social_risk_factors)
```

### Real-Time Monitoring Systems

#### 1. Mempool Analysis
- Monitor pending transactions for attack patterns
- Detect MEV opportunities being exploited
- Identify coordination between multiple pending transactions
- Alert on unusual gas price patterns

#### 2. Cross-Chain Coordination Detection
- Monitor bridge transactions for unusual patterns
- Detect coordinated cross-chain activities
- Track large value movements across chains
- Identify potential cross-chain laundering

#### 3. DeFi Protocol Integration
- Real-time monitoring of flash loan transactions
- Detection of oracle manipulation attempts
- Governance proposal analysis for malicious content
- Liquidity pool monitoring for rug pull indicators

---

## Behavioral Risk Scoring

### Multi-Dimensional Risk Assessment

#### 1. Financial Risk Indicators
```
Financial Behavior Score = (
    Flash_Loan_Usage_Score * 0.25 +
    Unusual_Volume_Score * 0.20 +
    MEV_Extraction_Score * 0.15 +
    Cross_Protocol_Score * 0.15 +
    Timing_Anomaly_Score * 0.15 +
    Profit_Pattern_Score * 0.10
)
```

#### 2. Social Risk Indicators
```
Social Behavior Score = (
    Community_Reports_Score * 0.30 +
    Project_Association_Score * 0.25 +
    Communication_Pattern_Score * 0.20 +
    Influence_Network_Score * 0.15 +
    Platform_Gaming_Score * 0.10
)
```

#### 3. Technical Risk Indicators
```
Technical Behavior Score = (
    Contract_Interaction_Score * 0.25 +
    Gas_Optimization_Score * 0.20 +
    Multi_Chain_Score * 0.20 +
    Privacy_Tool_Usage_Score * 0.15 +
    Infrastructure_Usage_Score * 0.10 +
    Bot_Behavior_Score * 0.10
)
```

### Composite Risk Calculation
```
Overall_Behavioral_Risk = (
    Financial_Risk * 0.40 +
    Technical_Risk * 0.35 +
    Social_Risk * 0.25
)

Risk_Categories:
- 0-25: Low Risk (Normal DeFi user behavior)
- 26-50: Medium Risk (Power user or possible suspicious activity)
- 51-75: High Risk (Likely malicious behavior, requires investigation)  
- 76-100: Critical Risk (Active threat, immediate action recommended)
```

### Confidence Scoring
```
Confidence_Level = (
    Data_Quality_Score * 0.30 +
    Pattern_Consistency_Score * 0.25 +
    Multi_Source_Confirmation_Score * 0.20 +
    Historical_Validation_Score * 0.15 +
    Expert_Review_Score * 0.10
)
```

---

## Implementation Guidelines

### 1. Behavioral Monitoring Pipeline
```
Data Collection → Pattern Recognition → Risk Assessment → Alert Generation → Response Actions
```

### 2. Integration with Existing Systems
- IOC databases for static indicator correlation
- Traditional threat intelligence for attribution
- Social media monitoring for campaign detection
- Exchange data for off-chain correlation

### 3. Privacy and Legal Considerations
- Behavioral analysis on public blockchain data only
- Anonymization of detection algorithms
- Compliance with data protection regulations
- Transparent scoring methodologies

### 4. Continuous Model Improvement
- Regular pattern validation against known attacks
- Community feedback integration for false positive reduction
- Adaptive scoring based on ecosystem evolution
- Regular model retraining with new attack vectors

---

This behavioral catalog serves as a comprehensive reference for identifying and responding to malicious activities in Web3 environments. Unlike static IOCs, these behavioral patterns provide early warning systems and proactive protection mechanisms for the decentralized ecosystem.