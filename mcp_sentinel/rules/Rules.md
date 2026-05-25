# RULES.md — mcp-sentinel Rule Reference

Complete reference for all 150 detection rules in mcp-sentinel.
Rules are grouped by category. Each entry includes the rule ID, severity, detection targets, framework mappings, description, and remediation guidance.

**Legend:**
🔴 CRITICAL · 🟠 HIGH · 🟡 MEDIUM · 🟢 LOW  |  ✅ active · 🧪 experimental

---

## Quick Reference

| ID | Status | Sev | Name | Category |
|---|---|---|---|---|
| [MCPS-001](#mcps001) | ✅ | 🔴 | Tool Poisoning via Description Field | `tool-integrity` |
| [MCPS-002](#mcps002) | ✅ | 🔴 | Secret and Token Exposure in Tool Definitions | `secret-management` |
| [MCPS-003](#mcps003) | ✅ | 🟠 | Overly Permissive Parameter Schemas | `least-privilege` |
| [MCPS-004](#mcps004) | ✅ | 🟠 | Insecure Transport Configuration | `transport-security` |
| [MCPS-005](#mcps005) | ✅ | 🟠 | Agentic Supply Chain: Unverified Tool Provenance | `supply-chain` |
| [MCPS-006](#mcps006) | 🧪 | 🔴 | Hidden Instructions in Tool Annotations | `tool-integrity` |
| [MCPS-007](#mcps007) | 🧪 | 🔴 | LLM Jailbreak Trigger Language in Tool Definitions | `tool-integrity` |
| [MCPS-008](#mcps008) | 🧪 | 🔴 | Credentials Embedded in Server URL | `secret-management` |
| [MCPS-009](#mcps009) | 🧪 | 🟠 | Dangerous Tool Name Indicating Direct System Access | `least-privilege` |
| [MCPS-010](#mcps010) | 🧪 | 🟠 | Server-Side Request Forgery via Unrestricted URL Parameter | `injection` |
| [MCPS-011](#mcps011) | 🧪 | 🟠 | Unfiltered External Content Pass-Through | `output-handling` |
| [MCPS-012](#mcps012) | 🧪 | 🟡 | Internal Network Infrastructure Disclosure | `information-disclosure` |
| [MCPS-013](#mcps013) | 🧪 | 🟠 | Unrestricted Filesystem Access Pattern in Tool Description | `excessive-permissions` |
| [MCPS-014](#mcps014) | 🧪 | 🟡 | Bulk or Unfiltered Data Return Pattern | `data-exposure` |
| [MCPS-015](#mcps015) | 🧪 | 🟠 | Insecure Webhook or Callback URL Parameter | `injection` |
| [MCPS-016](#mcps016) | 🧪 | 🔴 | Capability Self-Grant in Tool Definition | `tool-integrity` |
| [MCPS-017](#mcps017) | 🧪 | 🟠 | Tool Memory Write and Persistence Pattern | `context-manipulation` |
| [MCPS-018](#mcps018) | 🧪 | 🟡 | Numeric Parameter Without Range Constraints | `resource-control` |
| [MCPS-019](#mcps019) | 🧪 | 🔴 | Executable Code or Script Parameter | `injection` |
| [MCPS-020](#mcps020) | 🧪 | 🟠 | Placeholder and Default Credential Values in Tool Parameters | `secret-management` |
| [MCPS-021](#mcps021) | 🧪 | 🟠 | Misconfigured Cross-Origin and CORS Policies | `access-control` |
| [MCPS-022](#mcps022) | 🧪 | 🟡 | Insufficient Logging and Monitoring Indicators | `logging-monitoring` |
| [MCPS-023](#mcps023) | 🧪 | 🟠 | Missing Human Oversight for High-Risk Operations | `human-oversight` |
| [MCPS-024](#mcps024) | 🧪 | 🟠 | Cross-Agent Instruction Propagation Risk | `multi-agent-security` |
| [MCPS-025](#mcps025) | 🧪 | 🟠 | Unauthenticated Cross-Agent Communication | `agent-authentication` |
| [MCPS-026](#mcps026) | 🧪 | 🟠 | Untrusted External Source References in Tool Definitions | `supply-chain` |
| [MCPS-027](#mcps027) | 🧪 | 🟠 | Data and Model Poisoning Patterns in Tool Definitions | `data-integrity` |
| [MCPS-028](#mcps028) | 🧪 | 🟡 | Misleading Security Claims in Tool Metadata | `misinformation` |
| [MCPS-030](#mcps030) | 🧪 | 🟠 | Cloud and AI Service Enumeration via MCP Tools | `reconnaissance` |
| [MCPS-031](#mcps031) | 🧪 | 🟠 | Credential Harvesting via Agent Tool Definitions | `credential-access` |
| [MCPS-032](#mcps032) | 🧪 | 🟠 | RAG Poisoning via Tool Description Injection | `rag-integrity` |
| [MCPS-033](#mcps033) | 🧪 | 🔴 | Destructive Tool Invocation via MCP Definition | `impact-data-destruction` |
| [MCPS-034](#mcps034) | 🧪 | 🟠 | Trusted Output Manipulation via Tool Metadata | `output-integrity` |
| [MCPS-035](#mcps035) | 🧪 | 🟠 | Deferred Malicious Instructions in Tool Definitions | `defense-evasion` |
| [MCPS-036](#mcps036) | 🧪 | 🟠 | Supply Chain Rug Pull via Package Update | `supply-chain` |
| [MCPS-037](#mcps037) | 🧪 | 🟡 | Public Code Repository Exposure in MCP Definitions | `reconnaissance` |
| [MCPS-038](#mcps038) | 🧪 | 🟠 | LLM Prompt Crafting via MCP Definition Poisoning | `prompt-injection` |
| [MCPS-039](#mcps039) | 🧪 | 🟠 | Unrestricted Data Access via AI Agent Tools | `data-access-control` |
| [MCPS-040](#mcps040) | 🧪 | 🟠 | Unrestricted AI Agent Tool Access Definition | `tool-permissions` |
| [MCPS-041](#mcps041) | 🧪 | 🟠 | Covert AI Agent C2 via Hidden Instructions | `command-and-control` |
| [MCPS-042](#mcps042) | 🧪 | 🟠 | Supply Chain Poisoned MCP Tool Definition | `supply-chain-integrity` |
| [MCPS-043](#mcps043) | 🧪 | 🟡 | Agent Configuration Leakage via Metadata | `information-disclosure` |
| [MCPS-044](#mcps044) | 🧪 | 🟡 | Agent Tool Discovery and Capability Enumeration | `information-disclosure` |
| [MCPS-045](#mcps045) | 🧪 | 🟠 | Hardcoded Application Access Tokens in MCP Definitions | `authentication-security` |
| [MCPS-046](#mcps046) | 🧪 | 🟠 | Unauthorized AI Agent Deployment Configuration | `agent-deployment` |
| [MCPS-047](#mcps047) | 🧪 | 🟠 | Drive-by Compromise via Web-Fetching Tools | `initial-access` |
| [MCPS-048](#mcps048) | 🧪 | 🟠 | Sensitive Data Exposure via Tool Configuration | `data-leakage` |
| [MCPS-049](#mcps049) | 🧪 | 🟠 | Crafted Retrieval Content in MCP Definitions | `retrieval-integrity` |
| [MCPS-050](#mcps050) | 🧪 | 🟠 | Poisoned Training Data Ingestion via MCP Tools | `data-integrity` |
| [MCPS-051](#mcps051) | 🧪 | 🟠 | Delimiter Confusion via Special Character Sets | `prompt-injection` |
| [MCPS-052](#mcps052) | 🧪 | 🟠 | MCP Server Chat History Manipulation Capability | `defense-evasion` |
| [MCPS-053](#mcps053) | 🧪 | 🟠 | MCP Tool Facilitating Dynamic AI Command Generation | `ai-command-generation` |
| [MCPS-054](#mcps054) | 🧪 | 🟠 | Detection of Unsafe Execution Sinks in Call Chains | `call-chain-analysis` |
| [MCPS-055](#mcps055) | 🧪 | 🟠 | Phishing via Impersonation and Social Engineering | `social-engineering` |
| [MCPS-056](#mcps056) | 🧪 | 🟠 | Supply Chain Compromise via Unpinned Dependencies | `supply-chain-integrity` |
| [MCPS-057](#mcps057) | 🧪 | 🔴 | Self-Replicating Prompt Injection in Tool Definitions | `prompt-integrity` |
| [MCPS-058](#mcps058) | 🧪 | 🟡 | Unverified Entity Generation Enabling Hallucination Discovery | `llm-safety` |
| [MCPS-059](#mcps059) | 🧪 | 🟠 | Suspicious System Instruction Keywords in Tool Definitions | `tool-integrity` |
| [MCPS-060](#mcps060) | 🧪 | 🟡 | LLM System Information Discovery via Tool Definitions | `discovery` |
| [MCPS-061](#mcps061) | 🧪 | 🟡 | Chaff Data Spamming via Tool Definitions | `resource-abuse` |
| [MCPS-062](#mcps062) | 🧪 | 🟡 | MCP Tool Attack Verification and Probing | `attack-staging` |
| [MCPS-063](#mcps063) | 🧪 | 🟠 | System Prompt Exposure in MCP Definitions | `prompt-security` |
| [MCPS-064](#mcps064) | 🧪 | 🟠 | Detection of Unauthorized AI Service Proxy Endpoints | `infrastructure-integrity` |
| [MCPS-065](#mcps065) | 🧪 | 🟠 | Active Scanning via MCP Tool Definitions | `reconnaissance` |
| [MCPS-066](#mcps066) | 🧪 | 🔴 | Hardcoded Credentials in MCP Server Definition | `credential-exposure` |
| [MCPS-067](#mcps067) | 🧪 | 🟠 | Staged Capabilities via External Registry References | `supply-chain` |
| [MCPS-068](#mcps068) | 🧪 | 🟠 | Detects Tools Capable of Generating Deepfakes | `ai-safety` |
| [MCPS-069](#mcps069) | 🧪 | 🟠 | Unbounded Input Schema Enables Resource Exhaustion | `input-validation` |
| [MCPS-070](#mcps070) | 🧪 | 🟠 | Deepfake Phishing Facilitation via MCP Tools | `ai-media-safety` |
| [MCPS-071](#mcps071) | 🧪 | 🟠 | MCP Server Proxy Model Staging Detection | `ai-attack-staging` |
| [MCPS-072](#mcps072) | 🧪 | 🔴 | Model Poisoning via Unverified Weights and Data | `model-integrity` |
| [MCPS-073](#mcps073) | 🧪 | 🟠 | Overly Permissive Local Agent Tool Definitions | `agent-permissions` |
| [MCPS-074](#mcps074) | 🧪 | 🟡 | Unrestricted Process Enumeration Tool | `system-enumeration` |
| [MCPS-075](#mcps075) | 🧪 | 🟠 | Black-Box Transfer via Adversarial Input Crafting | `adversarial-robustness` |
| [MCPS-076](#mcps076) | 🧪 | 🟠 | Unsafe AI Artifact Loading via Serialization | `artifact-integrity` |
| [MCPS-077](#mcps077) | 🧪 | 🟠 | Unrestricted API Querying for Black-Box Optimization | `api-abuse` |
| [MCPS-078](#mcps078) | 🧪 | 🔴 | Host Escape via Disabled Safety Controls | `privilege-escalation` |
| [MCPS-079](#mcps079) | 🧪 | 🟠 | Adversarial Evasion Triggers in MCP Definitions | `ai-evasion` |
| [MCPS-080](#mcps080) | 🧪 | 🟠 | MCP Tool Impersonation via Deceptive Metadata | `identity-impersonation` |
| [MCPS-081](#mcps081) | 🧪 | 🟠 | Adversarial Data Crafting via Tool Definitions | `input-validation` |
| [MCPS-082](#mcps082) | 🧪 | 🟡 | Embedded Knowledge Leakage in MCP Definitions | `information-disclosure` |
| [MCPS-083](#mcps083) | 🧪 | 🟠 | Sandbox and VM Evasion in Tool Definitions | `defense-evasion` |
| [MCPS-084](#mcps084) | 🧪 | 🟠 | Deceptive Agent Baiting via Tool Metadata | `agent-manipulation` |
| [MCPS-085](#mcps085) | 🧪 | 🟠 | Malicious Link Execution in MCP Definitions | `url-integrity` |
| [MCPS-086](#mcps086) | 🧪 | 🟠 | Reputation Inflation via Fabricated Trust Signals | `supply-chain-trust` |
| [MCPS-087](#mcps087) | 🧪 | 🟠 | Model Replication via Unrestricted Inference Tools | `model-extraction` |
| [MCPS-088](#mcps088) | 🧪 | 🟠 | AI Model and Dataset Exfiltration via MCP Tools | `ai-ip-theft` |
| [MCPS-089](#mcps089) | 🧪 | 🟠 | Unrestricted RAG Database Access via MCP Tools | `data-access-control` |
| [MCPS-090](#mcps090) | 🧪 | 🔴 | MCP Server Machine Compromise via Tool Execution | `system-integrity` |
| [MCPS-091](#mcps091) | 🧪 | 🟠 | Model Extraction via Unrestricted Query Tools | `model-integrity` |
| [MCPS-092](#mcps092) | 🧪 | 🟡 | Exposed Dataset and Model Artifact References | `data-exposure` |
| [MCPS-093](#mcps093) | 🧪 | 🟠 | LLM Social Engineering via Tool Metadata | `social-engineering` |
| [MCPS-094](#mcps094) | 🧪 | 🟡 | Model Artifact Exposure in MCP Definitions | `model-artifact-exposure` |
| [MCPS-095](#mcps095) | 🧪 | 🟠 | User Execution via Unsafe MCP Artifacts | `execution-control` |
| [MCPS-096](#mcps096) | 🧪 | 🟠 | Exfiltration via Unrestricted AI Inference API | `data-exfiltration` |
| [MCPS-097](#mcps097) | 🧪 | 🟠 | Model Inversion via Confidence Score Exposure | `model-inversion` |
| [MCPS-098](#mcps098) | 🧪 | 🟠 | Malicious Dependency in MCP Server Packages | `supply-chain` |
| [MCPS-099](#mcps099) | 🧪 | 🟠 | Hardcoded Credentials in MCP Server Definition | `credential-exposure` |
| [MCPS-100](#mcps100) | 🧪 | 🟠 | Untrusted Data Ingestion in Tool Definitions | `data-integrity` |
| [MCPS-101](#mcps101) | 🧪 | 🟡 | MCP Tool Schema Lacks Adversarial Input Guards | `model-integrity` |
| [MCPS-102](#mcps102) | 🧪 | 🟠 | Unrestricted Repository Data Access in MCP Tools | `data-collection` |
| [MCPS-103](#mcps103) | 🧪 | 🟠 | Backdoor Trigger Injection in Tool Definitions | `tool-integrity` |
| [MCPS-104](#mcps104) | 🧪 | 🟠 | Uncontrolled MCP Tool Activation Triggers | `trigger-control` |
| [MCPS-105](#mcps105) | 🧪 | 🟠 | Adversarial AI Attack Vector Detection | `model-integrity` |
| [MCPS-106](#mcps106) | 🧪 | 🟠 | Compromised Model Loading via Untrusted Dependencies | `model-supply-chain` |
| [MCPS-107](#mcps107) | 🧪 | 🟠 | Indirect AI Model Access via Third-Party Service | `ai-model-access` |
| [MCPS-108](#mcps108) | 🧪 | 🟠 | MCP Artifact Masquerading via Metadata Spoofing | `defense-evasion` |
| [MCPS-109](#mcps109) | 🧪 | 🔴 | Model Manipulation and Weight Poisoning Detection | `model-integrity` |
| [MCPS-110](#mcps110) | 🧪 | 🟠 | Adversarial AI Library Dependency Detection | `supply-chain-security` |
| [MCPS-111](#mcps111) | 🧪 | 🟠 | Repurposed Software Tools for AI Attacks | `tool-integrity` |
| [MCPS-112](#mcps112) | 🧪 | 🟠 | Adversarial Input Crafting via Unconstrained Tool Schemas | `input-validation` |
| [MCPS-113](#mcps113) | 🧪 | 🟡 | Exposure of AI Model Outputs in MCP Definitions | `information-disclosure` |
| [MCPS-114](#mcps114) | 🧪 | 🟡 | RAG Data Source Enumeration via MCP Definitions | `reconnaissance` |
| [MCPS-115](#mcps115) | 🧪 | 🟠 | Data Exfiltration via External Endpoints | `data-exfiltration` |
| [MCPS-116](#mcps116) | 🧪 | 🟠 | AI Artifact Collection via MCP Exposure | `artifact-exposure` |
| [MCPS-117](#mcps117) | 🧪 | 🟡 | Exposure of Public AI Artifacts in MCP Definitions | `information-disclosure` |
| [MCPS-118](#mcps118) | 🧪 | 🟠 | White-Box Model Access and Input Exposure | `model-access-control` |
| [MCPS-119](#mcps119) | 🧪 | 🟠 | Poisoned Model Distribution via MCP Server | `supply-chain` |
| [MCPS-120](#mcps120) | 🧪 | 🟠 | Financial Fraud and Identity Bypass Detection | `financial-security` |
| [MCPS-121](#mcps121) | 🧪 | 🟠 | User Data Exfiltration and Harm via MCP Tools | `user-harm` |
| [MCPS-122](#mcps122) | 🧪 | 🟠 | Exposed MCP Server Endpoint Without Authentication | `server-exposure` |
| [MCPS-029](#mcps029) | 🧪 | 🟠 | Covert Data Exfiltration via Rendered Image URLs | `data-exfiltration` |
| [MCPS-132](#mcps132) | 🧪 | 🟠 | RAG Credential Harvesting via Unfiltered Ingestion | `credential-access` |
| [MCPS-133](#mcps133) | 🧪 | 🟠 | Hardcoded Credentials in MCP Configuration | `credential-access` |
| [MCPS-134](#mcps134) | 🧪 | 🟠 | Data Exfiltration via Tool Input Parameters | `data-exfiltration` |
| [MCPS-135](#mcps135) | 🧪 | 🟠 | Prompt Infiltration via Untrusted Data Ingestion | `data-ingestion` |
| [MCPS-136](#mcps136) | 🧪 | 🟠 | Supply Chain Poisoned MCP Tool Detection | `supply-chain` |
| [MCPS-137](#mcps137) | 🧪 | 🟠 | Supply Chain Compromise via Poisoned MCP Tool | `supply-chain` |
| [MCPS-138](#mcps138) | 🧪 | 🟠 | AI Agent Configuration Tampering Detection | `configuration-integrity` |
| [MCPS-139](#mcps139) | 🧪 | 🟠 | Exposed AI Agent Configuration and Secrets | `configuration-exposure` |
| [MCPS-140](#mcps140) | 🧪 | 🟡 | Agentic Resource Consumption via Tool Directives | `resource-abuse` |
| [MCPS-141](#mcps141) | 🧪 | 🟠 | Persistent Memory Manipulation via MCP Tools | `memory-integrity` |
| [MCPS-142](#mcps142) | 🧪 | 🟠 | Unsecured AI Inference API Exposure in MCP Tools | `api-access-control` |
| [MCPS-143](#mcps143) | 🧪 | 🟠 | Cost Harvesting via Unbounded Tool Execution | `resource-abuse` |
| [MCPS-144](#mcps144) | 🧪 | 🔴 | MCP Tool Definition Prompt Injection Detection | `prompt-injection` |
| [MCPS-145](#mcps145) | 🧪 | 🟠 | OS Credential Dumping via MCP Tool Definitions | `credential-access` |
| [MCPS-146](#mcps146) | 🧪 | 🔴 | MCP Tool Definition Supply Chain Poisoning | `supply-chain-integrity` |
| [MCPS-147](#mcps147) | 🧪 | 🟠 | Triggered Prompt Injection via Event Hooks | `prompt-injection` |
| [MCPS-148](#mcps148) | 🧪 | 🟠 | Data Poisoning via Untrusted Tool Data Sources | `data-integrity` |
| [MCPS-149](#mcps149) | 🧪 | 🔴 | Direct Prompt Injection via Tool Metadata | `prompt-injection` |
| [MCPS-150](#mcps150) | 🧪 | 🔴 | Indirect Prompt Injection via External Data Ingestion | `prompt-injection` |
| [MCPS-123](#mcps123) | 🧪 | 🟠 | AI Software Supply Chain Compromise via MCP Packages | `supply-chain-integrity` |
| [MCPS-124](#mcps124) | 🧪 | 🟠 | Unrestricted Tool Invocation & Code Execution | `tool-execution` |
| [MCPS-125](#mcps125) | 🧪 | 🟠 | MCP Tool Definition Jailbreak Prompt Detection | `safety-bypass` |
| [MCPS-126](#mcps126) | 🧪 | 🟠 | System Prompt Extraction via Tool Definitions | `prompt-exfiltration` |
| [MCPS-127](#mcps127) | 🧪 | 🟠 | Suspicious Generative AI Model Integration | `ai-model-integrity` |
| [MCPS-128](#mcps128) | 🧪 | 🟠 | Prompt Obfuscation via Encoding and Hidden Characters | `defense-evasion` |
| [MCPS-129](#mcps129) | 🧪 | 🟠 | False RAG Entry Injection via MCP Ingestion Tools | `rag-integrity` |
| [MCPS-130](#mcps130) | 🧪 | 🟠 | AI Agent Context Poisoning via Tool Definitions | `context-poisoning` |
| [MCPS-131](#mcps131) | 🧪 | 🟠 | Persistent Thread Poisoning via Tool Definitions | `context-integrity` |

---

---

## Rule Details

### Tool Integrity

#### MCPS-001 · Tool Poisoning via Description Field

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** ✅ active &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `MCP02` · `ASI02` · `LLM01` · `AML.T0051` · `MANAGE 2.4`

MCP tool description fields are treated as authoritative context by the LLM. A malicious or compromised server may embed hidden instructions in these fields to redirect agent behavior, override system prompts, exfiltrate conversation content, or grant itself elevated capabilities. This is the most direct path from a compromised tool definition to full agent compromise.

**Remediation:** (1) Validate all tool descriptions against an allowlist of safe structural patterns before registering the tool. (2) Enforce a maximum character length on descriptions. (3) Scan for invisible Unicode characters at load time. (4) Pin and verify tool definitions against a known-good hash on each load. (5) Use LLM-assisted semantic analysis as a second pass for subtle manipulation.

**Tags:** `tool-poisoning` `prompt-injection` `static` `supply-chain`

---

#### MCPS-006 · Hidden Instructions in Tool Annotations

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.annotations`

**Maps to:** `MCP02` · `ASI02` · `LLM01` · `AML.T0051`

Tool annotation fields receive the same LLM trust as description fields but are scrutinized far less during security review. Adversaries can embed hidden directives in annotations to redirect agent behavior, override system prompts, or exfiltrate context content while the visible description appears benign. Annotations are a blind spot in most MCP security tooling.

**Remediation:** (1) Apply the same validation pipeline to annotation fields as to description fields. (2) Treat annotations as untrusted input from the server operator. (3) Enforce maximum annotation length. (4) Scan for invisible Unicode. (5) Consider stripping or escaping annotations before passing to the LLM context.

**Tags:** `tool-poisoning` `prompt-injection` `annotations` `static`

---

#### MCPS-007 · LLM Jailbreak Trigger Language in Tool Definitions

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `tool.annotations`

**Maps to:** `AML.T0054` · `MCP02` · `LLM01` · `ASI06` · `MANAGE 2.4`

Tool definitions may embed jailbreak trigger phrases designed to disable safety constraints or override training-level guardrails in the LLM processing the definition. Phrases associated with known jailbreak techniques (DAN, developer mode, unrestricted mode) in a tool definition indicate a deliberate attempt to bypass model-level safety controls.

**Remediation:** (1) Maintain and update a blocklist of known jailbreak trigger phrases. (2) Use LLM-assisted semantic analysis to detect novel jailbreak framings. (3) Reject any tool definition containing confirmed jailbreak language. (4) Alert on pattern matches for security team review regardless of context. (5) Do not attempt to sanitize; reject and quarantine the definition.

**Tags:** `jailbreak` `prompt-injection` `tool-poisoning` `static`

---

#### MCPS-016 · Capability Self-Grant in Tool Definition

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `MCP02` · `ASI05` · `LLM01` · `AML.T0051`

Tool definitions containing language that explicitly grants the LLM new permissions, elevated access, or capabilities beyond its baseline represent a deliberate attempt to escalate agent privileges through the tool layer. Unlike general instruction injection (MCPS-001), this targets the permission model specifically, attempting to expand what the agent is authorized to do within the system.

**Remediation:** (1) Treat any tool definition containing permission grant language as malicious and reject it. (2) Permissions are granted by system design and cannot be legitimately declared in a tool description. (3) Alert the security team immediately for investigation of the source. (4) Audit all tools from the same origin for additional poisoning.

**Tags:** `privilege-escalation` `tool-poisoning` `capability-grant` `static`

---

#### MCPS-059 · Suspicious System Instruction Keywords in Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `tool.inputSchema`

**Maps to:** `AML.T0069.001` · `MCP02` · `LLM01`

MCP tool definitions may contain keywords that mimic internal LLM system directives or function names. Adversaries embed these terms to manipulate the model's decision-making process, triggering unauthorized tool invocations or bypassing safety constraints. This technique is frequently leveraged in indirect prompt injection and RAG poisoning attacks.

**Remediation:** (1) Audit all tool metadata for LLM control keywords and system directive mimics. (2) Sanitize descriptions, names, and schema properties against known injection patterns. (3) Implement strict allowlists for tool invocation and parameter validation. (4) Monitor agent logs for anomalous tool call sequences triggered by external content.

**Tags:** `llm-manipulation` `prompt-injection` `static` `tool-integrity` `rag-poisoning`

---

#### MCPS-103 · Backdoor Trigger Injection in Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `tool.inputSchema`

**Maps to:** `AML.T0043.004` · `MCP02`

MCP tool definitions may contain hidden backdoor triggers designed to activate specific model behaviors when certain inputs are provided. These triggers are often obfuscated using zero-width characters, encoded strings, or conditional language that appears benign to humans but manipulates inference outcomes.

**Remediation:** (1) Validate AI models for backdoor triggers using adversarial testing and concept drift monitoring. (2) Preprocess all inference data to strip adversarial perturbations and invisible characters. (3) Implement input validation and adversarial detection algorithms prior to model inference. (4) Use ensemble methods and model hardening techniques to increase robustness against trigger-based attacks.

**Tags:** `backdoor` `trigger-injection` `static` `model-hardening` `adversarial-input`

---

#### MCPS-111 · Repurposed Software Tools for AI Attacks

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `tool.inputSchema`

**Maps to:** `AML.T0016.001` · `MCP08`

Adversaries repurpose or modify legitimate software tools to attack AI systems, such as creating reverse proxies for LLM access or injecting deepfakes to bypass biometric verification. This rule detects MCP tool definitions that indicate malicious repurposing, unauthorized access capabilities, or biometric evasion techniques.

**Remediation:** (1) Audit all third-party MCP tools for unauthorized modifications. (2) Enforce strict input validation and schema constraints. (3) Monitor tool behavior for reverse proxy or data exfiltration patterns. (4) Verify tool signatures against trusted registries.

**Tags:** `repurposed-tools` `ai-attack` `static` `supply-chain`

---

### Secret Management

#### MCPS-002 · Secret and Token Exposure in Tool Definitions

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** ✅ active &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.env`, `server.config`

**Maps to:** `MCP01` · `LLM02` · `AML.T0048` · `GOVERN 1.1` · `ASI08`

Hard-coded credentials, API keys, connection strings, or long-lived tokens embedded in MCP server definitions expose sensitive environments to unauthorized access. Attackers can retrieve these through prompt injection, compromised context windows, or debug traces. The LLM itself may reproduce embedded credentials in its outputs.

**Remediation:** (1) Never embed credentials in tool definitions; use environment variable references resolved at runtime outside the MCP schema. (2) Integrate secret-scanning into your CI pipeline. (3) Use short-lived, scoped credentials with automatic rotation. (4) Apply field-level redaction before any tool schema is sent to the model.

**Tags:** `secrets` `token-exposure` `static` `credential-hygiene`

---

#### MCPS-008 · Credentials Embedded in Server URL

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.url`

**Maps to:** `MCP01` · `LLM02` · `AML.T0048` · `GOVERN 1.1`

Server URLs containing embedded credentials (http://user:password@host) expose those credentials in plain text to any system that reads the server definition, including the LLM context, log files, and debug traces. This is a distinct attack surface from hard-coded credentials in parameter defaults: the URL is parsed by the transport layer before any schema validation runs.

**Remediation:** (1) Never embed credentials in URLs; use dedicated auth configuration fields. (2) If auth is required, inject credentials at runtime from a secrets manager. (3) Scan all server definition files for URL credential patterns in CI. (4) Rotate any credentials found embedded in a server definition immediately.

**Tags:** `secrets` `url-credentials` `static` `credential-hygiene`

---

#### MCPS-020 · Placeholder and Default Credential Values in Tool Parameters

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.inputSchema`, `server.env`

**Maps to:** `MCP01` · `LLM02` · `ASI04` · `AML.T0010` · `GOVERN 1.1`

Tool parameter default values containing placeholder, test, or example credentials indicate that a real credential was expected but not yet provided. These placeholders are sometimes inadvertently left in production definitions. They also indicate the parameter accepts credentials as input, which creates a separate injection and leakage risk. Both patterns warrant immediate remediation.

**Remediation:** (1) Remove all default values from credential parameters. (2) Require credentials to be injected at runtime from a secrets manager. (3) If a placeholder must exist, use a value that fails fast (e.g., an empty string that triggers an auth error) rather than a silently accepted dummy value. (4) Block deployment if placeholder patterns are detected.

**Tags:** `secrets` `placeholder-credentials` `static` `credential-hygiene`

---

### Least Privilege

#### MCPS-003 · Overly Permissive Parameter Schemas

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** ✅ active &nbsp;|&nbsp; **Targets:** `tool.inputSchema`

**Maps to:** `MCP04` · `ASI02` · `LLM07` · `AML.T0051` · `MANAGE 1.3`

MCP tools that accept unrestricted string parameters for shell commands, file paths, SQL queries, or URLs create a direct channel from agent-controlled input to privileged system operations. When an agent is induced to call such a tool with attacker-controlled values, the result is injection at the tool layer. JSON Schema constraints are the primary static mitigation.

**Remediation:** (1) Apply enum constraints to parameters with a known valid value set. (2) Apply regex pattern constraints to string fields. (3) Set maxLength on all free-text inputs. (4) Set additionalProperties: false on all schemas. (5) Validate server-side even if schema constraints exist.

**Tags:** `injection` `parameter-validation` `least-privilege` `static`

---

#### MCPS-009 · Dangerous Tool Name Indicating Direct System Access

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.name`

**Maps to:** `MCP03` · `ASI02` · `LLM06` · `MAP 1.6`

Tool names containing keywords associated with direct system access (shell execution, administrative access, privilege escalation) indicate tools with elevated capability that require additional scrutiny. While a dangerous name alone does not confirm a vulnerability, it is a strong signal that the tool's input schema must be fully constrained and its justification documented. Unnamed or generically named high-privilege tools are a supply chain red flag.

**Remediation:** (1) Require documented business justification for any tool with a name matching these patterns. (2) Ensure such tools have fully constrained input schemas with no unrestricted string parameters. (3) Apply additional runtime approval gates before invocation. (4) Prefer descriptive, narrowly-scoped tool names that reflect their actual function.

**Tags:** `tool-name` `least-privilege` `dangerous-capability` `static`

---

### Transport Security

#### MCPS-004 · Insecure Transport Configuration

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** ✅ active &nbsp;|&nbsp; **Targets:** `server.url`, `server.transport`

**Maps to:** `MCP05` · `LLM09` · `AML.T0010` · `MEASURE 2.5`

MCP servers communicating over plaintext HTTP expose all tool invocations, parameters, results, and credentials to network interception. In agentic workflows, a single intercepted tool call can yield session tokens, PII, or the ability to inject malicious tool results back to the agent. WebSocket servers without origin validation are vulnerable to cross-site WebSocket hijacking.

**Remediation:** (1) Require TLS (HTTPS/WSS) for all non-localhost MCP server endpoints. (2) Enforce certificate validation. (3) For WebSocket servers, configure a strict origins allowlist. (4) Consider mTLS for server-to-server MCP communication in production environments.

**Tags:** `transport` `tls` `network` `static`

---

### Supply Chain

#### MCPS-005 · Agentic Supply Chain: Unverified Tool Provenance

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** ✅ active &nbsp;|&nbsp; **Targets:** `server.packages[]`

**Maps to:** `MCP08` · `ASI04` · `LLM05` · `AML.T0010` · `MAP 1.6`

MCP ecosystems compose tools at runtime from external registries and packages without inherent verification. A compromised dependency, poisoned registry entry, or impersonating server can silently alter agent behavior. Unpinned version specifiers allow compromised updates to be automatically adopted on next restart with no alert and no audit log entry.

**Remediation:** (1) Pin all dependencies to exact versions with integrity hashes. (2) Maintain an approved origins allowlist for remote MCP server URLs. (3) Implement signed manifests for tool definitions verified at load time. (4) Use curated private registries rather than public ones for production.

**Tags:** `supply-chain` `provenance` `integrity` `static` `agentic`

---

#### MCPS-026 · Untrusted External Source References in Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `LLM03` · `MCP08` · `ASI04` · `AML.T0010`

Tool descriptions or annotations that reference unofficial, third-party, community, or unverified packages and integrations are a supply chain signal. While not inherently malicious, these references indicate dependencies outside the organization's vetted supply chain, and their presence in tool metadata suggests the tool may load or depend on unaudited external components.

**Remediation:** (1) Remove references to unofficial or unverified external sources from tool definitions. (2) Vet all third-party integrations before including them in tool metadata. (3) Prefer internal or organization-approved package registries. (4) Add supply chain scanning to CI/CD for all tool definitions.

**Tags:** `supply-chain` `external-dependency` `static`

---

#### MCPS-036 · Supply Chain Rug Pull via Package Update

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.packages[]`, `server.url`

**Maps to:** `AML.T0109` · `MCP08`

Adversaries publish legitimate MCP server packages or dependencies, gain user trust, and later push malicious updates that compromise agent behavior or exfiltrate data. Static analysis can detect missing integrity checks, unpinned versions, or suspicious registry endpoints that facilitate undetected supply chain compromises.

**Remediation:** (1) Enforce strict version pinning for all MCP server dependencies. (2) Require cryptographic signatures or integrity hashes for package updates. (3) Validate package sources against official registries. (4) Implement automated monitoring for unexpected package changes or metadata anomalies.

**Tags:** `supply-chain` `rug-pull` `package-integrity` `static`

---

#### MCPS-067 · Staged Capabilities via External Registry References

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `server.url`, `server.packages[]`

**Maps to:** `AML.T0079` · `MCP08`

MCP server definitions may reference external infrastructure, registries, or web services to stage malicious capabilities like poisoned models, datasets, or prompt injections. These staged artifacts can be loaded at runtime to compromise agent behavior or exfiltrate data.

**Remediation:** (1) Audit all external URLs and package references in server definitions. (2) Validate referenced registries and artifacts against known-good hashes or signatures. (3) Scan descriptions and metadata for invisible Unicode and exfiltration keywords. (4) Restrict MCP servers to allowlisted infrastructure.

**Tags:** `supply-chain` `capability-staging` `static` `prompt-injection`

---

#### MCPS-098 · Malicious Dependency in MCP Server Packages

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.packages[]`

**Maps to:** `AML.T0011.001` · `MCP08`

MCP server definitions may declare external software packages that introduce malicious code or vulnerable dependencies. Adversaries exploit unpinned versions, hallucinated package names, or unverified registries to compromise the agent's runtime environment.

**Remediation:** (1) Enforce strict version pinning and cryptographic signature verification for all dependencies. (2) Restrict library loading to trusted registries and validate package integrity via checksums. (3) Maintain an AI Bill of Materials (AIBOM) to track provenance and enable rapid vulnerability response. (4) Train developers on supply chain risks and hallucinated package identification.

**Tags:** `supply-chain` `dependency-management` `static` `package-integrity`

---

#### MCPS-119 · Poisoned Model Distribution via MCP Server

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.url`, `server.packages[]`, `tool.description`

**Maps to:** `AML.T0058` · `MCP08` · `LLM06`

MCP server definitions may reference or bundle poisoned machine learning models from untrusted registries. Adversaries distribute these models to compromise downstream AI agents or exfiltrate data when the model is loaded or invoked during tool execution.

**Remediation:** (1) Maintain an AI Bill of Materials (AI BOM) tracking all model artifacts and dependencies. (2) Enforce cryptographic verification of model weights and checkpoints before loading. (3) Restrict model sources to allowlisted, trusted registries with provenance tracking. (4) Scan downloaded models for malicious payloads using static analysis tools like Picklescan.

**Tags:** `supply-chain` `model-poisoning` `static` `ai-bom`

---

#### MCPS-136 · Supply Chain Poisoned MCP Tool Detection

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `server.packages[]`, `server.url`

**Maps to:** `AML.T0104` · `MCP08` · `AGT04`

Adversaries distribute malicious MCP tool definitions through package registries, version control repositories, or remote servers. These poisoned tools often embed covert instructions or prompt injections within descriptions and docstrings to manipulate agent behavior, exfiltrate data, or execute unauthorized commands. Static analysis can identify suspicious behavioral directives and unpinned dependencies that facilitate supply chain compromises.

**Remediation:** (1) Verify tool publishers and package signatures before integration. (2) Pin all dependency versions and avoid wildcard constraints. (3) Scan tool descriptions and docstrings for covert instructions or prompt injection patterns. (4) Restrict remote MCP server connections to allowlisted, verified domains.

**Tags:** `supply-chain` `tool-poisoning` `prompt-injection` `static`

---

#### MCPS-137 · Supply Chain Compromise via Poisoned MCP Tool

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `server.packages[]`, `server.url`

**Maps to:** `AML.T0010.005` · `MCP08` · `LLM06`

Adversaries compromise AI agent capabilities by distributing poisoned MCP tool definitions through package registries or remote servers. These malicious tools often embed covert prompt injections or exfiltration instructions within tool descriptions and metadata, manipulating agent behavior to steal data or execute unauthorized commands.

**Remediation:** (1) Pin all MCP server and tool dependencies to specific, verified commit hashes or version tags. (2) Validate tool descriptions and docstrings against a strict allowlist of expected capabilities. (3) Scan package registries and remote server URLs for known malicious indicators before integration. (4) Implement runtime sandboxing for agent tool execution.

**Tags:** `supply-chain` `tool-poisoning` `static` `dependency-risk`

---

### Injection

#### MCPS-010 · Server-Side Request Forgery via Unrestricted URL Parameter

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.inputSchema`

**Maps to:** `MCP04` · `LLM05` · `AML.T0040` · `MANAGE 1.3`

MCP tools that accept arbitrary URLs or endpoints as string parameters without format constraints, allowlists, or scheme validation enable server-side request forgery (SSRF). When an agent is induced to call such a tool with an attacker-controlled URL, the server becomes a proxy for requests to internal network resources, cloud metadata endpoints, or other services not accessible to the agent directly.

**Remediation:** (1) Replace free-form URL parameters with an enum of allowed endpoints. (2) If dynamic URLs are required, validate against an allowlist of permitted schemes, hostnames, and paths server-side. (3) Block requests to RFC-1918 address ranges, loopback, and cloud metadata endpoints (169.254.169.254). (4) Use a dedicated HTTP client with SSRF protections.

**Tags:** `ssrf` `injection` `url-validation` `static`

---

#### MCPS-015 · Insecure Webhook or Callback URL Parameter

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.inputSchema`

**Maps to:** `MCP04` · `LLM05` · `AML.T0040` · `MANAGE 1.3`

Tools that accept webhook or callback URLs as unconstrained string parameters allow an adversary to redirect notifications or events to an attacker-controlled server. This enables credential harvesting (if auth tokens are sent with the callback), exfiltration of event payloads, and SSRF to internal endpoints. Webhook endpoints must be validated against an allowlist of approved domains.

**Remediation:** (1) Validate webhook URLs against an allowlist of approved domains. (2) Reject any URL that is not HTTPS or resolves to a private address. (3) Sign webhook payloads so recipients can verify authenticity. (4) Require explicit pre-registration of callback endpoints before use.

**Tags:** `ssrf` `webhook` `callback` `injection` `static`

---

#### MCPS-019 · Executable Code or Script Parameter

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.inputSchema`

**Maps to:** `MCP04` · `ASI02` · `LLM05` · `AML.T0051` · `MANAGE 1.3`

Tool parameters explicitly accepting code, scripts, expressions, or functions for server-side evaluation represent one of the highest-risk patterns in MCP tool design. When an agent is induced to populate such a parameter with attacker-controlled content, the result is direct arbitrary code execution on the server. These parameters are inherently dangerous and should be eliminated in favor of structured, enumerable alternatives wherever possible.

**Remediation:** (1) Eliminate code/script parameters wherever possible; replace with structured operation enums. (2) If dynamic code execution is unavoidable, sandbox execution in an isolated environment with no network access. (3) Implement an allowlist of permitted operations rather than free-form code. (4) Apply static analysis to all code before execution. (5) Never execute agent-generated code directly on the server.

**Tags:** `code-execution` `injection` `rce` `static`

---

### Output Handling

#### MCPS-011 · Unfiltered External Content Pass-Through

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`

**Maps to:** `MCP07` · `LLM05` · `ASI08` · `AML.T0051`

Tools described as passing through, proxying, or returning raw external content without modification introduce a prompt injection vector via tool results. Adversarially crafted external content (web pages, API responses, documents) returned verbatim to the agent context may contain instructions the agent will follow. This is the primary vector for indirect prompt injection attacks.

**Remediation:** (1) Never return external content verbatim to the agent context. (2) Extract only the required structured fields from external responses. (3) Apply output filtering to detect and strip instruction injection patterns. (4) Use a content extraction layer that converts raw content to structured data. (5) Flag tools returning HTML, markdown, or freeform text for additional review.

**Tags:** `indirect-injection` `output-handling` `pass-through` `static`

---

### Information Disclosure

#### MCPS-012 · Internal Network Infrastructure Disclosure

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `server.url`

**Maps to:** `MCP07` · `LLM02` · `MAP 1.6`

Tool descriptions, parameter defaults, or server URLs containing private IP addresses or internal domain names expose network topology to any system that reads the server definition. This information can be used to pivot to internal resources, identify SSRF targets, or map the internal network. Internal hostnames in tool definitions also indicate the tool has connectivity to non-public systems.

**Remediation:** (1) Replace hardcoded internal addresses with environment variable references. (2) Use service discovery mechanisms rather than hardcoded hostnames. (3) Audit all tool definitions for infrastructure references before publishing. (4) Treat any tool definition containing internal addresses as potentially sensitive and restrict its distribution accordingly.

**Tags:** `information-disclosure` `internal-network` `static`

---

#### MCPS-043 · Agent Configuration Leakage via Metadata

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `server.env.*`

**Maps to:** `AML.T0084` · `MCP02`

MCP tool descriptions and server metadata may inadvertently expose internal configuration details, system prompts, or capability inventories. Adversaries leverage this information to map the agent's architecture, identify accessible services, and plan targeted exploitation.

**Remediation:** (1) Audit tool descriptions and annotations for verbose capability lists. (2) Remove internal architecture, system prompt, or configuration references from metadata. (3) Enforce strict schema validation to prevent configuration leakage.

**Tags:** `information-disclosure` `discovery` `static`

---

#### MCPS-044 · Agent Tool Discovery and Capability Enumeration

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `tool.inputSchema`

**Maps to:** `AML.T0084.001` · `MCP02`

MCP server definitions often expose detailed tool capabilities, backend integrations, and data access levels. Adversaries analyze these definitions to map agent permissions, identify sensitive data sources like cloud storage or email systems, and locate potential exfiltration pathways. Overly verbose or unfiltered tool metadata significantly increases the attack surface for reconnaissance-driven attacks.

**Remediation:** (1) Minimize tool descriptions to functional necessities only. (2) Remove references to specific backend systems, data stores, or administrative privileges. (3) Implement role-based tool visibility in MCP server configurations. (4) Regularly audit tool definitions for information leakage.

**Tags:** `reconnaissance` `tool-enumeration` `static` `information-disclosure`

---

#### MCPS-082 · Embedded Knowledge Leakage in MCP Definitions

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `server.url`

**Maps to:** `AML.T0084.000` · `MCP02`

MCP server definitions may inadvertently expose details about underlying data sources, proprietary knowledge bases, or internal systems. Adversaries analyze these definitions to map agent capabilities and identify high-value targets for data exfiltration or targeted prompt injection. This reconnaissance enables precise attacks against exposed knowledge boundaries.

**Remediation:** (1) Audit tool descriptions and annotations to remove references to internal systems, proprietary databases, or sensitive data sources. (2) Implement strict content policies for MCP definition authoring that prohibit architectural or data-source disclosure. (3) Use automated scanning to flag overly verbose or revealing metadata before deployment. (4) Restrict agent knowledge boundaries via runtime configuration rather than static definitions.

**Tags:** `reconnaissance` `info-disclosure` `static` `knowledge-mapping`

---

#### MCPS-113 · Exposure of AI Model Outputs in MCP Definitions

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `server.env.*`, `tool.inputSchema`

**Maps to:** `AML.T0063` · `MCP06`

MCP server and tool definitions may inadvertently expose internal AI model outputs, confidence scores, or debug flags. These artifacts enable adversaries to reverse-engineer model decision boundaries and craft evasion attacks. Static analysis detects verbose logging configurations and explicit references to raw model scoring in metadata.

**Remediation:** (1) Apply passive AI output obfuscation to strip confidence scores and raw probabilities from tool responses. (2) Encrypt sensitive model metadata and restrict debug or verbose logging in production environments. (3) Enforce strict access controls and authentication for all API endpoints and model queries. (4) Deploy models in centralized cloud environments rather than edge devices to limit adversary access to internal outputs.

**Tags:** `discovery` `information-disclosure` `model-outputs` `static`

---

#### MCPS-117 · Exposure of Public AI Artifacts in MCP Definitions

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `server.packages[]`, `tool.annotations`

**Maps to:** `AML.T0002` · `MCP02`

MCP server definitions may inadvertently reference or expose public AI artifacts such as model weights, training datasets, or agent configurations. Adversaries can harvest these references to reconstruct the victim's AI stack, create proxy models, or craft targeted adversarial inputs.

**Remediation:** (1) Limit public release of technical information about the AI stack. (2) Restrict access to model repositories and datasets using authentication and authorization. (3) Remove references to training data, model weights, or agent configurations from public-facing tool descriptions. (4) Monitor access logs for unauthorized artifact retrieval.

**Tags:** `information-disclosure` `ai-artifacts` `static` `resource-development`

---

### Excessive Permissions

#### MCPS-013 · Unrestricted Filesystem Access Pattern in Tool Description

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`

**Maps to:** `MCP03` · `ASI05` · `LLM06` · `MANAGE 1.3`

Tool descriptions claiming to read, write, or execute arbitrary files across the filesystem without path restrictions indicate tools with excessive scope. Combined with unrestricted path parameters (flagged by MCPS-003), such tools create a direct path from agent-controlled input to arbitrary file read/write on the server. Filesystem access tools must declare a specific root directory constraint.

**Remediation:** (1) Restrict filesystem tools to a declared root directory or allowlisted paths. (2) Add path constraint language to tool descriptions (e.g., "within /workspace/"). (3) Enforce path validation server-side and reject traversal attempts. (4) Separate read-only and write operations into distinct tools with different permission requirements.

**Tags:** `filesystem` `excessive-permissions` `least-privilege` `static`

---

### Data Exposure

#### MCPS-014 · Bulk or Unfiltered Data Return Pattern

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`

**Maps to:** `MCP07` · `ASI08` · `LLM02` · `MEASURE 2.5`

Tools described as returning entire datasets, complete database contents, or unfiltered bulk responses expose large volumes of potentially sensitive data to the LLM context window. This creates risk of PII leakage through model outputs, context window overflow that can displace security-critical instructions, and cross-contamination where data from one query appears in responses to an unrelated query.

**Remediation:** (1) Implement mandatory pagination on all data-returning tools. (2) Apply field-level filtering to return only required attributes. (3) Set a maximum result count in the tool's input schema. (4) Apply PII detection before returning data to the agent context. (5) Prefer search-and-retrieve patterns over full-scan patterns.

**Tags:** `data-exposure` `bulk-return` `information-disclosure` `static`

---

#### MCPS-092 · Exposed Dataset and Model Artifact References

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `server.url`, `server.env.*`, `tool.inputSchema`

**Maps to:** `AML.T0002.000` · `LLM06`

MCP server definitions may inadvertently expose URLs or paths to training datasets, model checkpoints, or internal data repositories. Adversaries can harvest these references to replicate models, craft adversarial examples, or tailor attacks against the victim organization. Limiting public release of such artifacts reduces the attack surface for model inversion and data poisoning.

**Remediation:** (1) Audit MCP server definitions for exposed dataset or model artifact URLs. (2) Restrict public release of training data, model checkpoints, and technical project details. (3) Implement access controls and authentication for any referenced data repositories. (4) Use opaque identifiers instead of direct storage paths in tool schemas.

**Tags:** `data-exposure` `model-replication` `static` `reconnaissance`

---

### Context Manipulation

#### MCPS-017 · Tool Memory Write and Persistence Pattern

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`

**Maps to:** `MCP06` · `ASI01` · `LLM01` · `AML.T0051` · `MANAGE 2.4`

Tools described as writing to the model's memory, persisting context, or modifying the agent's long-term state create a persistent injection vector. An adversary who can control the content written to memory can influence future sessions, cause the agent to follow attacker-defined instructions in subsequent conversations, and persist a compromise across session boundaries. This maps to MITRE ATLAS techniques for context manipulation.

**Remediation:** (1) Require explicit human approval before any tool writes to persistent agent memory. (2) Implement read-only memory in agent systems where possible. (3) Validate and sanitize content before it is written to any persistent store. (4) Audit all memory write operations and alert on unexpected content. (5) Implement memory expiry and regular sanitization cycles.

**Tags:** `memory-poisoning` `context-manipulation` `persistence` `static`

---

### Resource Control

#### MCPS-018 · Numeric Parameter Without Range Constraints

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.inputSchema`

**Maps to:** `MCP04` · `ASI10` · `LLM10` · `MANAGE 1.3`

Integer and number parameters controlling counts, limits, depths, timeouts, or sizes without minimum and maximum constraints allow agents (or adversaries who have influenced an agent) to pass extreme values that trigger resource exhaustion, denial of service, or unexpected behavior. Unbounded numeric inputs are a common oversight in tool schemas that prioritize functionality over defense-in-depth.

**Remediation:** (1) Add minimum and maximum constraints to all integer and number parameters. (2) Use conservative maximums (e.g., count <= 100, timeout <= 30s) as defaults. (3) Implement server-side enforcement independent of schema constraints. (4) Consider using enum for commonly bounded values (page size, result limit).

**Tags:** `resource-control` `dos` `numeric-bounds` `static`

---

### Access Control

#### MCPS-021 · Misconfigured Cross-Origin and CORS Policies

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.config`, `server.url`

**Maps to:** `MCP09` · `GOVERN 1.1`

MCP servers that accept connections from any origin, use wildcard CORS policies, or lack WebSocket origin validation are vulnerable to cross-site request forgery and cross-site WebSocket hijacking. A malicious web page can silently invoke tools using the victim's session context without the user's knowledge or consent.

**Remediation:** (1) Configure WebSocket servers with an explicit origins allowlist. (2) Set restrictive CORS headers on all HTTP endpoints. (3) Reject WebSocket upgrade requests from unlisted origins. (4) Avoid serving MCP endpoints on ports accessible to browser contexts without authentication.

**Tags:** `cors` `websocket` `access-control` `csrf` `static`

---

### Logging Monitoring

#### MCPS-022 · Insufficient Logging and Monitoring Indicators

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `MCP10` · `ASI09` · `MEASURE 2.5`

Tool definitions that explicitly state they do not log, audit, or monitor invocations provide no basis for detecting compromise or auditing agent behavior. Declarations of "no logging" in tool metadata are themselves a risk signal: legitimate tools rarely advertise this, while malicious tools may do so to discourage detection.

**Remediation:** (1) Remove any language indicating logging is disabled or suppressed. (2) Implement structured audit logging for all tool invocations. (3) Log caller identity, parameters (with PII redacted), and results. (4) Alert on anomalous tool call patterns using the audit log as a baseline.

**Tags:** `logging` `monitoring` `audit` `static`

---

### Human Oversight

#### MCPS-023 · Missing Human Oversight for High-Risk Operations

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `ASI03` · `MCP03` · `LLM06` · `GOVERN 1.7`

Tools described as executing irreversible or high-impact actions without human approval or review create direct risk when an agent is manipulated. Descriptions that acknowledge operating without oversight are a significant signal: adversarial inputs that reach such a tool cause immediate harm with no intervention opportunity.

**Remediation:** (1) Add explicit human confirmation requirements to all tools that perform irreversible actions. (2) Document approval workflows in tool descriptions. (3) Implement a preview-before-execute pattern. (4) Require separate acknowledgment of irreversibility before destructive operations proceed.

**Tags:** `human-oversight` `irreversible-action` `approval-gate` `static`

---

### Multi Agent Security

#### MCPS-024 · Cross-Agent Instruction Propagation Risk

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `ASI07` · `MCP02` · `LLM01` · `AML.T0051`

Tools designed to relay, forward, or broadcast instructions between agents create a propagation path for prompt injection. Because inter-agent messages are typically trusted implicitly, an attacker who can influence one agent's output can inject instructions into all downstream agents through these relay tools. The trust boundary disappears once a relay tool is in the pipeline.

**Remediation:** (1) Validate and sanitize all content before forwarding between agents. (2) Avoid relay tools that pass agent output verbatim. (3) Apply instruction injection detection at every agent boundary. (4) Design multi-agent pipelines with explicit trust boundaries and content isolation between agents.

**Tags:** `multi-agent` `prompt-injection` `relay` `trust-boundary` `static`

---

### Agent Authentication

#### MCPS-025 · Unauthenticated Cross-Agent Communication

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `server.transport`

**Maps to:** `ASI09` · `MCP05` · `GOVERN 1.1`

Tools or server configurations that explicitly describe or enable agent-to-agent communication without authentication or integrity verification allow adversaries to impersonate agents and inject rogue instructions into orchestration pipelines. Unlike human-to-agent channels, agent-to-agent channels are rarely monitored and impersonation is difficult to detect after the fact.

**Remediation:** (1) Require mutual authentication for all agent-to-agent communication. (2) Sign all inter-agent messages and verify signatures at each hop. (3) Use TLS (WSS/HTTPS) for all agent communication channels. (4) Log all inter-agent message exchanges for audit purposes.

**Tags:** `cross-agent` `authentication` `message-integrity` `static`

---

### Data Integrity

#### MCPS-027 · Data and Model Poisoning Patterns in Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `LLM04` · `MCP02` · `AML.T0051` · `MANAGE 2.4`

Tool definitions containing language associated with data or model poisoning — modifying training data, corrupting model weights, or injecting backdoor triggers — indicate tools that could be used to compromise downstream AI systems. Even descriptive mentions in tool metadata are a risk signal when the tool has write access to data pipelines or model artifacts.

**Remediation:** (1) Reject tool definitions containing poisoning or model-modification language unless explicitly authorized. (2) Restrict write access to training pipelines and model artifact stores. (3) Audit all tools with access to data or model artifacts. (4) Implement data provenance tracking to detect unexpected modifications.

**Tags:** `data-poisoning` `model-integrity` `code-injection` `static`

---

#### MCPS-050 · Poisoned Training Data Ingestion via MCP Tools

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.inputSchema`, `tool.description`, `server.env.*`

**Maps to:** `AML.T0020` · `LLM06`

MCP servers may define tools or resources that ingest external datasets for model fine-tuning or active learning. Adversaries exploit unvalidated data pipelines to inject poisoned samples, backdoor triggers, or malicious labels into the training corpus. This compromises model integrity and enables covert behavior manipulation during inference.

**Remediation:** (1) Sanitize all ingested training data prior to model updates. (2) Implement strict access controls and provenance tracking for datasets. (3) Validate model behavior against known backdoor triggers and monitor for concept drift. (4) Maintain an AI Bill of Materials to track dataset lineage and integrity.

**Tags:** `data-poisoning` `supply-chain` `model-integrity` `static`

---

#### MCPS-100 · Untrusted Data Ingestion in Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.packages[]`

**Maps to:** `AML.T0010.002` · `MCP08`

MCP servers that ingest or process external datasets and training data without validation create supply chain vulnerabilities. Adversaries can poison these data sources to compromise model behavior or inject malicious payloads. Static analysis identifies tool definitions and schemas that accept untrusted data without sanitization constraints.

**Remediation:** (1) Implement strict access controls on internal model registries and training data repositories. (2) Sanitize all ingested datasets prior to processing using content filters and anomaly detection. (3) Verify cryptographic checksums of all AI artifacts and dataset sources. (4) Maintain detailed provenance records for all training data and modifications.

**Tags:** `data-poisoning` `supply-chain` `static` `input-validation`

---

#### MCPS-148 · Data Poisoning via Untrusted Tool Data Sources

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `tool.annotations`

**Maps to:** `AML.T0099` · `MCP02` · `LLM06`

MCP tools that ingest or reference external data sources without strict validation can be exploited to poison agent context. Adversaries place malicious or misleading content in locations the tool queries, causing persistent manipulation of AI agent decisions across sessions.

**Remediation:** (1) Validate and sanitize all external data sources referenced by tools. (2) Enforce strict input schema constraints including format, pattern, and length limits. (3) Implement allowlisting for trusted data repositories. (4) Monitor tool outputs for anomalous or poisoned content.

**Tags:** `data-poisoning` `persistence` `input-validation` `static`

---

### Misinformation

#### MCPS-028 · Misleading Security Claims in Tool Metadata

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `LLM09` · `MCP02` · `GOVERN 1.1`

Tool definitions containing overconfident or unverifiable security guarantees ("100% secure", "automatically encrypted", "FIPS certified") may cause agents and developers to over-trust the tool and skip independent security validation. This maps to the LLM misinformation risk applied to tool metadata: the tool's own description becomes the source of false security assurances.

**Remediation:** (1) Remove absolute security guarantee language from tool descriptions. (2) Replace compliance claims with links to documented evidence. (3) Require independent verification of any security property claimed in tool metadata. (4) Treat overconfident security language as a potential social engineering indicator.

**Tags:** `misinformation` `security-claims` `hallucination` `static`

---

### Reconnaissance

#### MCPS-030 · Cloud and AI Service Enumeration via MCP Tools

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.name`, `tool.description`, `tool.inputSchema`, `server.url`

**Maps to:** `AML.T0075` · `MCP02`

MCP server definitions may expose tools or resources that enumerate cloud infrastructure, AI models, or API endpoints. Adversaries leverage such capabilities to map the target environment, identify valuable AIaaS resources, and plan subsequent exploitation. Static analysis detects definitions containing broad discovery or enumeration functions.

**Remediation:** (1) Restrict tool capabilities to specific, scoped operations. (2) Remove or disable broad enumeration functions in MCP definitions. (3) Implement least-privilege access controls for cloud and AI provider credentials. (4) Audit server URLs and tool descriptions for reconnaissance indicators.

**Tags:** `reconnaissance` `cloud-discovery` `ai-enumeration` `static`

---

#### MCPS-037 · Public Code Repository Exposure in MCP Definitions

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.url`, `tool.description`, `server.packages[]`, `server.env.*`

**Maps to:** `AML.T0095.000` · `MCP07`

MCP server and tool definitions may inadvertently expose references to public code repositories, revealing victim infrastructure, AI frameworks, or internal project structures. Adversaries leverage these references for reconnaissance to map target environments, discover AI agent configurations, or identify leaked credentials and API keys.

**Remediation:** (1) Remove hardcoded repository URLs and credentials from MCP definitions. (2) Use environment variables or secure secret managers for authentication tokens. (3) Implement strict allowlists for external resource references. (4) Audit tool descriptions and package fields for unintended information disclosure.

**Tags:** `reconnaissance` `data-leakage` `static` `supply-chain`

---

#### MCPS-065 · Active Scanning via MCP Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `server.url`, `server.transport`

**Maps to:** `AML.T0006` · `MCP01`

MCP server definitions may expose tools or configurations that enable active scanning of internal networks or external targets. Adversaries leverage these exposed capabilities to probe for open ports, enumerate services, or gather intelligence without direct system interaction. This rule detects reconnaissance-oriented tool descriptions and insecure server endpoints that facilitate active scanning.

**Remediation:** (1) Restrict tool capabilities to prevent network scanning or service enumeration. (2) Enforce authentication and network segmentation for all MCP server endpoints. (3) Audit server URLs and transport configurations to block internal or debug exposure. (4) Implement allowlists for approved reconnaissance tools.

**Tags:** `reconnaissance` `active-scanning` `static` `network-exposure`

---

#### MCPS-114 · RAG Data Source Enumeration via MCP Definitions

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `server.url`, `tool.inputSchema`

**Maps to:** `AML.T0064` · `LLM06`

MCP server definitions may inadvertently expose references to retrieval augmented generation (RAG) pipelines, vector stores, or external data ingestion sources. Adversaries analyze these definitions to identify and target the underlying data repositories for poisoning or manipulation.

**Remediation:** (1) Remove explicit references to RAG pipelines or data sources from tool descriptions. (2) Abstract data ingestion details in server configurations. (3) Implement strict access controls on vector stores and knowledge bases. (4) Audit MCP definitions for unintended data exposure.

**Tags:** `reconnaissance` `rag` `data-exposure` `static`

---

### Credential Access

#### MCPS-031 · Credential Harvesting via Agent Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.env.*`

**Maps to:** `AML.T0098` · `MCP02`

MCP tool definitions may inadvertently grant AI agents access to credential stores, configuration files, or sensitive environment variables. Adversaries exploit overly permissive tool scopes or embedded instructions to harvest secrets from connected repositories, document stores, and local applications.

**Remediation:** (1) Segment AI agent components using container isolation and strict API access controls. (2) Limit tool invocation rates and restrict network and resource access within execution sandboxes. (3) Validate and cryptographically sign all MCP tool definitions to prevent poisoned docstrings. (4) Audit environment variables and input schemas to enforce minimal privilege and explicit credential exclusion.

**Tags:** `credential-harvesting` `tool-poisoning` `static` `credential-access`

---

#### MCPS-132 · RAG Credential Harvesting via Unfiltered Ingestion

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.env.*`

**Maps to:** `AML.T0082` · `LLM06` · `AG02`

MCP server definitions may expose RAG or knowledge base tools that ingest internal documents without sensitivity filtering. Adversaries can leverage these configurations to retrieve credentials, API keys, or secrets inadvertently stored in indexed documents. This vulnerability enables indirect credential access through AI agent context retrieval and prompt injection vectors.

**Remediation:** (1) Implement strict data filtering and sensitivity scanning before ingesting documents into RAG or knowledge base systems. (2) Configure privileged AI agent permissions to restrict access to credential-storing repositories. (3) Enforce single-user permission boundaries and lifecycle management for agents interacting with sensitive data. (4) Audit MCP tool definitions for missing access controls and unfiltered document retrieval capabilities.

**Tags:** `rag-security` `credential-harvesting` `static` `data-exfiltration`

---

#### MCPS-133 · Hardcoded Credentials in MCP Configuration

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.env.*`, `tool.inputSchema`, `server.url`

**Maps to:** `AML.T0083` · `MCP08`

MCP server and tool definitions often embed sensitive credentials like API keys, tokens, or database connection strings directly in configuration fields or environment variables. When these secrets are hardcoded or improperly masked, attackers who gain read access to the definition files can extract them to compromise downstream services. This vulnerability bypasses agent-level security controls by providing direct access to external infrastructure.

**Remediation:** (1) Remove hardcoded credentials from MCP definition files. (2) Use environment variables or a dedicated secret manager for sensitive values. (3) Implement pre-commit hooks to scan for secrets before deployment. (4) Restrict file permissions on configuration directories to prevent unauthorized reads.

**Tags:** `credential-access` `hardcoded-secrets` `configuration-security` `static`

---

#### MCPS-145 · OS Credential Dumping via MCP Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `tool.inputSchema`, `server.env.*`

**Maps to:** `AML.T0090` · `MCP01`

MCP tool definitions or server configurations may contain instructions or parameters designed to extract authentication tokens, environment variables, or memory contents from the host OS. These artifacts can facilitate credential harvesting for lateral movement across AI services and infrastructure.

**Remediation:** (1) Audit tool descriptions and input schemas for credential extraction keywords. (2) Restrict server environment variables to non-sensitive values. (3) Implement least-privilege execution contexts for MCP servers. (4) Monitor for unauthorized memory or keychain access attempts.

**Tags:** `credential-dumping` `os-access` `static` `credential-access`

---

### Rag Integrity

#### MCPS-032 · RAG Poisoning via Tool Description Injection

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `AML.T0070` · `LLM02`

MCP tool definitions may contain hidden instructions designed to be indexed by RAG systems. When retrieved during future queries, these payloads can override system prompts, exfiltrate data, or persist malicious behavior across sessions. This technique exploits the trust placed in indexed metadata and tool annotations.

**Remediation:** (1) Sanitize tool descriptions and annotations before indexing into RAG pipelines. (2) Implement content filtering and semantic validation for all ingested metadata. (3) Validate tool definitions against allowlisted publishers and signed manifests. (4) Monitor retrieval logs for anomalous query-response patterns.

**Tags:** `rag-poisoning` `prompt-injection` `static` `persistence`

---

#### MCPS-129 · False RAG Entry Injection via MCP Ingestion Tools

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.env.*`

**Maps to:** `AML.T0071` · `MCP02` · `LLM02`

MCP tools and resources configured for document ingestion may lack input sanitization, allowing adversaries to inject false RAG entries. These poisoned entries bypass monitoring and manipulate LLM responses during retrieval. The rule detects ingestion endpoints with weak schema constraints or metadata containing RAG manipulation keywords.

**Remediation:** (1) Implement strict input validation and sanitization for all document ingestion endpoints. (2) Enforce schema constraints including maxLength, format, and content-type filtering. (3) Deploy RAG-specific content filtering to detect and quarantine suspicious metadata or injection patterns. (4) Audit tool definitions for unconstrained text fields and restrict ingestion privileges.

**Tags:** `rag-poisoning` `defense-evasion` `static` `input-validation`

---

### Impact Data Destruction

#### MCPS-033 · Destructive Tool Invocation via MCP Definition

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `tool.inputSchema`

**Maps to:** `AML.T0101` · `MCP02`

MCP tool definitions may expose or enable mutative operations capable of mass data destruction or system wiping. Without explicit safety constraints or human-in-the-loop requirements, AI agents can autonomously invoke these tools to delete files, format volumes, or purge cloud resources. Static analysis identifies tools with destructive intent that lack proper permission boundaries or approval workflows.

**Remediation:** (1) Implement AI telemetry logging for tool invocations and agent decisions. (2) Enforce least-privilege permissions and restrict mutative tool access. (3) Require human-in-the-loop approval for destructive operations. (4) Validate tool definitions against signed manifests and scan for destructive intent.

**Tags:** `data-destruction` `impact` `tool-safety` `static`

---

### Output Integrity

#### MCPS-034 · Trusted Output Manipulation via Tool Metadata

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `tool.inputSchema`

**Maps to:** `AML.T0067`

MCP tool definitions may contain hidden instructions that manipulate the LLM's output to appear more authoritative or trustworthy. Adversaries embed prompts to fabricate citations, generate fake links, or use deceptive language, helping them evade user scrutiny and maintain persistence.

**Remediation:** (1) Audit tool descriptions and annotations for output manipulation instructions. (2) Implement strict output validation and citation verification pipelines. (3) Scan definitions for invisible Unicode and hidden payloads. (4) Enforce least-privilege tool capabilities.

**Tags:** `defense-evasion` `output-manipulation` `static` `citation-forgery`

---

### Defense Evasion

#### MCPS-035 · Deferred Malicious Instructions in Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `AML.T0094` · `MCP02` · `LLM01`

MCP tool definitions may contain conditional or deferred instructions designed to trigger only after a specific future event or conversation turn. This technique bypasses turn-based security controls that restrict tool invocation or data access when untrusted data first enters context.

**Remediation:** (1) Sanitize tool descriptions and annotations to remove conditional or deferred instruction patterns. (2) Implement turn-aware execution policies that inspect context history before allowing tool invocation. (3) Deploy static analysis scanning for temporal trigger keywords in MCP definitions.

**Tags:** `defense-evasion` `delayed-execution` `static` `prompt-injection`

---

#### MCPS-052 · MCP Server Chat History Manipulation Capability

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `tool.inputSchema`

**Maps to:** `AML.T0092` · `MCP02`

MCP servers defining tools that can read, edit, or delete LLM chat history may be leveraged by adversaries to cover tracks after compromising authentication tokens. These capabilities allow persistent context poisoning or conversation tampering without user visibility, especially in desktop clients that cache history. Static analysis identifies overly permissive history management tools in server definitions.

**Remediation:** (1) Restrict chat history modification tools to read-only access or require explicit user confirmation for write operations. (2) Enforce strict input validation, length limits, and content filtering on message and history fields. (3) Audit server configurations to remove unnecessary history sync or management capabilities. (4) Implement client-side history integrity checks and real-time synchronization validation to detect tampering.

**Tags:** `defense-evasion` `chat-history` `context-poisoning` `static`

---

#### MCPS-083 · Sandbox and VM Evasion in Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `tool.inputSchema`

**Maps to:** `AML.T0097` · `MCP02`

MCP tool definitions may contain instructions or logic designed to detect and bypass virtualization, sandbox, or analysis environments. Adversaries embed these checks to conceal malicious behavior during security scanning or automated analysis, altering agent execution based on environmental artifacts.

**Remediation:** (1) Audit tool descriptions and annotations for environmental checks or evasion logic. (2) Restrict tools from querying system environment variables or process lists. (3) Implement runtime sandboxing and strict execution boundaries for MCP tool invocation. (4) Validate definitions against known evasion signatures and signed manifests.

**Tags:** `sandbox-evasion` `defense-evasion` `static` `vm-detection`

---

#### MCPS-108 · MCP Artifact Masquerading via Metadata Spoofing

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.name`, `tool.description`, `server.url`

**Maps to:** `AML.T0074` · `MCP08`

Adversaries manipulate MCP tool names, descriptions, or server URLs to impersonate legitimate utilities, trusted vendors, or official services. This masquerading technique aims to bypass security controls and trick AI agents or users into invoking malicious components under the guise of benign functionality.

**Remediation:** (1) Verify tool and server names against a trusted allowlist. (2) Cross-reference publisher metadata with known-good registries. (3) Implement strict naming conventions and reject claims of unofficial legitimacy. (4) Audit server URLs for typosquatting or look-alike domains.

**Tags:** `masquerading` `defense-evasion` `metadata-spoofing` `static`

---

#### MCPS-128 · Prompt Obfuscation via Encoding and Hidden Characters

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.env.*`

**Maps to:** `AML.T0068` · `LLM02` · `MCP02`

Adversaries obfuscate malicious instructions within MCP tool definitions or resource metadata to bypass LLM guardrails and human review. This includes using encoding schemes like base64, embedding invisible Unicode characters, or leveraging visual obfuscation techniques in text fields.

**Remediation:** (1) Strip or decode encoded strings before processing. (2) Sanitize inputs to remove zero-width and invisible Unicode characters. (3) Enforce strict schema validation on tool descriptions and parameters. (4) Implement runtime guardrails that decode and scan obfuscated content.

**Tags:** `defense-evasion` `prompt-obfuscation` `static` `encoding-detection`

---

### Prompt Injection

#### MCPS-038 · LLM Prompt Crafting via MCP Definition Poisoning

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `prompt.description`, `server.env.*`

**Maps to:** `AML.T0065` · `MCP02` · `LLM01`

MCP server definitions may contain crafted prompts or tool descriptions designed to bypass AI safety guardrails. Adversaries embed exfiltration triggers or instruction override language directly into metadata fields, enabling persistent prompt injection and data leakage when the server is loaded.

**Remediation:** (1) Sanitize all prompt and description fields against known injection patterns. (2) Enforce strict input validation and length limits on tool schemas. (3) Implement runtime guardrails to detect exfiltration attempts via rendered content.

**Tags:** `prompt-crafting` `exfiltration` `static` `guardrail-bypass`

---

#### MCPS-051 · Delimiter Confusion via Special Character Sets

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `tool.inputSchema`

**Maps to:** `AML.T0069.000` · `LLM01`

MCP tool definitions may inadvertently expose or rely on fragile delimiter sets used by LLMs for context separation. Adversaries can exploit these special character sets to confuse parsing boundaries, leading to prompt injection or retrieval-augmented generation manipulation within the agent lifecycle.

**Remediation:** (1) Audit tool descriptions and schemas for ambiguous delimiter usage. (2) Replace fragile character sets with robust, schema-enforced boundaries. (3) Implement strict input validation and delimiter escaping in MCP server handlers. (4) Test definitions against known delimiter confusion payloads.

**Tags:** `delimiter-confusion` `prompt-injection` `rag-security` `static`

---

#### MCPS-144 · MCP Tool Definition Prompt Injection Detection

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `tool.inputSchema`

**Maps to:** `AML.T0051` · `MCP02` · `LLM01`

MCP tool definitions and annotations are ingested by the LLM as authoritative system context. Adversaries embed malicious instructions within these fields to override system prompts, bypass safety filters, or exfiltrate sensitive data during tool execution.

**Remediation:** (1) Implement input validation and sanitization for all tool definitions. (2) Deploy generative AI guardrails to filter malicious instructions. (3) Enforce strict access controls and authentication for MCP server endpoints. (4) Enable comprehensive telemetry logging to detect anomalous tool behavior. (5) Regularly audit and align model fine-tuning with safety guidelines.

**Tags:** `prompt-injection` `tool-poisoning` `static` `context-injection`

---

#### MCPS-147 · Triggered Prompt Injection via Event Hooks

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `tool.inputSchema`

**Maps to:** `AML.T0051.002` · `MCP02`

MCP tool definitions may embed latent instructions that activate only upon specific user interactions or system events. These triggered payloads are often obfuscated to evade static scanning and can hijack agent workflows for data exfiltration or lateral movement.

**Remediation:** (1) Implement strict input validation and schema enforcement for all tool parameters. (2) Enable comprehensive AI telemetry logging to monitor agent decision paths and tool invocations. (3) Sanitize tool descriptions and annotations to strip hidden or obfuscated instructions. (4) Deploy runtime monitoring to detect anomalous event-triggered behaviors.

**Tags:** `triggered-injection` `event-hook` `static` `prompt-injection` `obfuscation`

---

#### MCPS-149 · Direct Prompt Injection via Tool Metadata

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `tool.inputSchema`

**Maps to:** `AML.T0051.000` · `MCP02` · `LLM01`

Adversaries embed malicious instructions directly within MCP tool definitions, annotations, or input schemas. These static payloads bypass runtime input filters and manipulate the LLM context window, potentially leading to unauthorized tool execution, data exfiltration, or self-replicating worm behavior across connected agents.

**Remediation:** (1) Implement strict input and output validation for all tool definitions and schemas. (2) Enforce schema validation and data sanitization to strip unauthorized instructions. (3) Deploy AI telemetry logging to monitor tool invocation patterns and detect anomalous context manipulation. (4) Isolate agent environments to prevent self-replicating payloads from propagating.

**Tags:** `prompt-injection` `static` `tool-metadata` `context-manipulation`

---

#### MCPS-150 · Indirect Prompt Injection via External Data Ingestion

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.url`

**Maps to:** `AML.T0051.001` · `MCP02` · `LLM01`

MCP servers may define tools or resources that ingest external data from websites, databases, or email systems. Without strict input validation and sanitization, these data channels can carry hidden prompt injections that manipulate LLM behavior or exfiltrate sensitive context. This rule detects definitions that reference untrusted data ingestion or lack necessary validation constraints.

**Remediation:** (1) Implement strict input validation and schema enforcement for all externally ingested data. (2) Sanitize and strip hidden instructions or metadata before passing data to the LLM. (3) Enable AI telemetry logging to monitor tool inputs, outputs, and data access patterns. (4) Isolate untrusted data channels using sandboxed execution environments.

**Tags:** `indirect-injection` `data-ingestion` `static` `prompt-injection`

---

### Data Access Control

#### MCPS-039 · Unrestricted Data Access via AI Agent Tools

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `tool.annotations`

**Maps to:** `AML.T0085` · `MCP04` · `LLM07`

MCP tool definitions may grant AI agents overly broad access to internal data sources, RAG databases, or file systems. Without explicit scoping or filtering constraints, adversaries can abuse these tools to collect sensitive organizational data beyond normal user privileges.

**Remediation:** (1) Implement strict input validation and scoping constraints in tool input schemas. (2) Apply least-privilege access controls to AI agent tools and data sources. (3) Enable comprehensive telemetry logging for agent actions and data access. (4) Segment AI agent components and isolate sensitive data sources using sandboxing or API gateways.

**Tags:** `data-collection` `agent-permissions` `static` `rag-databases`

---

#### MCPS-089 · Unrestricted RAG Database Access via MCP Tools

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `tool.annotations`

**Maps to:** `AML.T0085.000` · `MCP02`

MCP tools configured to query RAG or vector databases may lack proper access controls, allowing adversaries to retrieve sensitive internal documents. This rule identifies tool definitions that expose broad document retrieval capabilities without explicit scoping or authentication constraints.

**Remediation:** (1) Implement AI telemetry logging for all RAG queries and agent actions. (2) Enforce privileged and single-user permission configurations to restrict data access. (3) Segment AI agent components and isolate vector store access with strict API controls. (4) Validate tool input schemas to require explicit scoping parameters such as tenant_id or user_role.

**Tags:** `rag-security` `data-exfiltration` `static` `access-control`

---

### Tool Permissions

#### MCPS-040 · Unrestricted AI Agent Tool Access Definition

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `tool.annotations`

**Maps to:** `AML.T0085.001` · `MCP02`

MCP tool definitions may grant AI agents overly broad access to internal APIs, databases, or external services without proper constraints. Adversaries can exploit these permissive configurations to exfiltrate sensitive data or perform unauthorized actions across organizational systems.

**Remediation:** (1) Implement comprehensive telemetry logging for all tool invocations, inputs, and outputs. (2) Apply principle of least privilege to AI agent permissions and tool access. (3) Enforce strict input validation and schema constraints on all tool definitions. (4) Segment AI agent components and isolate tool execution environments. (5) Regularly audit tool permissions and lifecycle management policies.

**Tags:** `agent-tools` `data-exfiltration` `permission-misconfiguration` `static`

---

### Command And Control

#### MCPS-041 · Covert AI Agent C2 via Hidden Instructions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `server.env.*`

**Maps to:** `AML.T0108` · `MCP02` · `LLM01`

MCP server definitions may contain hidden instructions or configuration parameters that enable AI agents to function as covert command and control channels. These patterns often instruct the agent to suppress output, bypass safety filters, or relay external commands without user visibility.

**Remediation:** (1) Audit tool descriptions and annotations for covert instructions. (2) Enforce strict input validation and output filtering on agent responses. (3) Restrict network and shell access in server configurations. (4) Implement runtime monitoring for anomalous agent behavior.

**Tags:** `command-and-control` `prompt-injection` `covert-channel` `static`

---

### Supply Chain Integrity

#### MCPS-042 · Supply Chain Poisoned MCP Tool Definition

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.packages[]`, `server.url`

**Maps to:** `AML.T0011.002` · `MCP08`

Adversaries compromise MCP tool definitions or server packages through supply chain attacks, injecting hidden instructions or malicious endpoints. When invoked by an AI agent, these poisoned tools can execute prompt injections, exfiltrate sensitive data, or run arbitrary commands. This rule scans tool metadata and dependency manifests for covert directives and unpinned packages.

**Remediation:** (1) Pin all server and tool dependencies to exact versions with cryptographic checksums. (2) Validate tool descriptions and input schemas against a strict allowlist of approved publishers. (3) Scan definitions for hidden instructions, invisible Unicode, and suspicious remote endpoints before deployment. (4) Implement runtime sandboxing for agent tool invocations to prevent arbitrary command execution.

**Tags:** `supply-chain` `tool-poisoning` `static` `dependency-risk`

---

#### MCPS-056 · Supply Chain Compromise via Unpinned Dependencies

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.packages[]`, `server.url`, `tool.inputSchema`

**Maps to:** `AML.T0010` · `MCP08`

MCP server definitions may reference external models, tools, or packages without cryptographic verification or version pinning. Adversaries exploit this by injecting malicious artifacts into registries or repositories, compromising the AI supply chain during initialization or runtime. This technique enables initial access through tainted dependencies or compromised model weights.

**Remediation:** (1) Verify cryptographic checksums and signatures for all AI artifacts and dependencies. (2) Implement an AI Bill of Materials (AI BOM) to track dataset provenance and component lineage. (3) Enforce strict version pinning and integrity constraints in server definitions. (4) Deploy generative AI guardrails to validate inputs and outputs from external models.

**Tags:** `supply-chain` `dependency-verification` `static` `initial-access`

---

#### MCPS-146 · MCP Tool Definition Supply Chain Poisoning

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.packages[]`

**Maps to:** `AML.T0110` · `MCP08`

Adversaries compromise MCP tool definitions through supply chain attacks, injecting hidden logic or modifying parameters to achieve persistence. Poisoned tools silently exfiltrate data, redirect agent outputs, or execute unauthorized commands while appearing legitimate. This technique leverages trusted package registries and unpinned dependencies to maintain long-term influence over AI agent workflows.

**Remediation:** (1) Pin all server package dependencies to exact versions or verified hashes. (2) Validate tool definitions against signed manifests before deployment. (3) Scan tool descriptions and input schemas for hidden exfiltration or redirect instructions. (4) Implement runtime monitoring for unexpected tool outputs or network calls.

**Tags:** `supply-chain` `tool-poisoning` `persistence` `static`

---

#### MCPS-123 · AI Software Supply Chain Compromise via MCP Packages

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.packages[]`, `server.env.*`

**Maps to:** `AML.T0010.001` · `MCP08`

MCP server definitions often declare external AI software dependencies. Adversaries exploit unpinned versions, missing integrity checks, or namesquatted and hallucinated package names to inject malicious code into the agent's runtime environment. This rule scans package declarations for supply chain vulnerabilities.

**Remediation:** (1) Pin all AI software dependencies to exact versions or commit hashes. (2) Enforce cryptographic signature verification and checksum validation for all packages. (3) Maintain an allowlist of approved package registries and reject internal or untrusted index URLs. (4) Audit package names against known hallucinated or namesquatted lists.

**Tags:** `supply-chain` `dependency-confusion` `static` `ai-software`

---

### Authentication Security

#### MCPS-045 · Hardcoded Application Access Tokens in MCP Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.env.*`, `tool.inputSchema`, `server.url`

**Maps to:** `AML.T0091.000` · `MCP01`

MCP server definitions may inadvertently expose or hardcode application access tokens used for AIaaS, SaaS, or cloud API authentication. If compromised, these tokens allow adversaries to bypass authentication, impersonate legitimate services, and access restricted data or manipulate LLM interactions. Static analysis detects hardcoded credentials, insecure token references, and overly permissive authentication scopes.

**Remediation:** (1) Remove all hardcoded tokens and secrets from MCP definition files. (2) Use secure secret management systems or environment variable injection at runtime. (3) Validate and scope tokens to minimum required permissions. (4) Implement token rotation and audit logging for all API interactions.

**Tags:** `authentication` `secret-management` `static` `token-exposure`

---

### Agent Deployment

#### MCPS-046 · Unauthorized AI Agent Deployment Configuration

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `server.env.*`

**Maps to:** `AML.T0103` · `MCP04` · `AI.RMF-03`

MCP server definitions can be manipulated to deploy AI agents with excessive permissions and destructive system prompts. Adversaries leverage these configurations to execute autonomous actions, bypass user safeguards, and compromise environment integrity without direct interaction. This static analysis detects malicious deployment directives and disabled safety controls within tool and server metadata.

**Remediation:** (1) Enforce strict permission boundaries for deployed agents. (2) Require explicit user confirmation for destructive or autonomous actions. (3) Validate system prompts and tool grants against a secure allowlist. (4) Monitor server definitions for unauthorized deployment configurations.

**Tags:** `agent-deployment` `execution` `static` `permission-escalation`

---

### Initial Access

#### MCPS-047 · Drive-by Compromise via Web-Fetching Tools

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `tool.name`

**Maps to:** `AML.T0078` · `MCP02` · `LLM06`

MCP tools that fetch, scrape, or render external web content can introduce indirect prompt injections into the agent's context. When untrusted web data is passed directly to the LLM without sanitization, adversaries can manipulate agent behavior, exfiltrate conversation history, or execute malicious commands. This rule identifies server definitions containing web-interaction capabilities lacking proper input validation.

**Remediation:** (1) Implement strict input validation and sanitization for all web-fetched content before passing it to the LLM. (2) Enforce allowlists for trusted domains and block execution of untrusted scripts or markdown. (3) Add content-type filtering and length limits to tool input schemas. (4) Isolate web-scraping tools in sandboxed environments with restricted network access.

**Tags:** `drive-by-compromise` `indirect-prompt-injection` `web-scraping` `static`

---

### Data Leakage

#### MCPS-048 · Sensitive Data Exposure via Tool Configuration

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.env.*`

**Maps to:** `AML.T0057` · `LLM06`

MCP tool definitions may inadvertently configure agents to retrieve or output sensitive information without proper safeguards. Adversaries exploit weak input validation or overly permissive tool descriptions to induce the LLM to exfiltrate private user data or proprietary training information.

**Remediation:** (1) Validate AI models for data leakage triggers and concept drift. (2) Implement generative AI guardrails to filter sensitive outputs. (3) Enforce safety guidelines in system prompts to restrict data exposure. (4) Align model training with security policies to prevent unintended disclosures.

**Tags:** `data-leakage` `exfiltration` `static` `llm-safety`

---

### Retrieval Integrity

#### MCPS-049 · Crafted Retrieval Content in MCP Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `AML.T0066` · `MCP02`

Adversaries craft MCP tool or resource descriptions to be ingested by RAG pipelines, embedding hidden instructions that activate upon retrieval. This technique abuses the LLM's trust in retrieved context to manipulate agent behavior, hijack queries, or exfiltrate sensitive data.

**Remediation:** (1) Sanitize all tool and resource descriptions before ingestion. (2) Implement strict allowlists for RAG content sources. (3) Deploy static analysis to scan for retrieval-triggered instructions. (4) Isolate LLM context from untrusted MCP metadata.

**Tags:** `rag-poisoning` `retrieval-crafting` `static` `context-manipulation`

---

### Ai Command Generation

#### MCPS-053 · MCP Tool Facilitating Dynamic AI Command Generation

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `tool.inputSchema`

**Maps to:** `AML.T0102` · `MCP02`

MCP tool definitions may expose capabilities that allow LLMs to dynamically synthesize and execute system commands. This technique leverages natural language inputs to generate adaptive attack payloads, bypassing static signature detection. Static analysis can identify tools configured for unstructured command generation or external AI orchestration.

**Remediation:** (1) Restrict tool capabilities to prevent unstructured command generation. (2) Implement strict input validation and allowlisting for execution contexts. (3) Monitor and audit AI model interactions for dynamic payload synthesis. (4) Enforce sandboxing for any tool claiming code or command generation capabilities.

**Tags:** `ai-command-generation` `dynamic-payloads` `static` `mcp-tool-audit`

---

### Call Chain Analysis

#### MCPS-054 · Detection of Unsafe Execution Sinks in Call Chains

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.env.*`

**Maps to:** `AML.T0084.003` · `MCP02` · `LLM02`

MCP tool definitions and server configurations may expose direct call chains that route LLM outputs or user inputs to dangerous execution sinks. These configurations create exploitable paths for remote code execution when combined with prompt injection attacks. Static analysis identifies references to unsafe functions and unvalidated data flows within tool metadata.

**Remediation:** (1) Audit tool definitions for direct references to execution functions. (2) Implement strict input validation and sandboxing for all tool parameters. (3) Decouple LLM outputs from system commands using intermediate validation layers. (4) Restrict framework agent configurations to approved, audited call chains.

**Tags:** `call-chain` `rce-prevention` `static` `execution-sink`

---

### Social Engineering

#### MCPS-055 · Phishing via Impersonation and Social Engineering

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `server.url`

**Maps to:** `AML.T0052` · `LLM05`

MCP tool definitions and server configurations may be crafted to impersonate legitimate services or use urgent social engineering language to trick users or agents into providing credentials or executing malicious actions. This technique leverages AI-generated text to scale targeted phishing campaigns within the MCP ecosystem.

**Remediation:** (1) Educate AI model developers and users on AI supply chain risks and phishing indicators. (2) Implement deepfake and synthetic content detection algorithms for untrusted inputs. (3) Validate tool publishers and server URLs against allowlists. (4) Enforce strict input validation and credential handling policies.

**Tags:** `phishing` `social-engineering` `impersonation` `static`

---

#### MCPS-093 · LLM Social Engineering via Tool Metadata

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `AML.T0052.000` · `MCP02` · `LLM01`

MCP tool definitions may contain descriptions or annotations that instruct the LLM to adopt a social engineering persona. These hidden directives can manipulate the model into soliciting sensitive credentials or personal data from users under the guise of legitimate tool functionality. Attackers leverage this to scale spearphishing campaigns and bypass standard security controls.

**Remediation:** (1) Educate users and developers on AI supply chain risks and social engineering tactics. (2) Implement deepfake and prompt injection detection algorithms for untrusted tool metadata. (3) Enforce strict validation and allowlisting of MCP tool definitions. (4) Monitor tool outputs for unauthorized credential solicitation.

**Tags:** `social-engineering` `prompt-injection` `credential-theft` `static`

---

### Prompt Integrity

#### MCPS-057 · Self-Replicating Prompt Injection in Tool Definitions

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `tool.inputSchema`

**Maps to:** `AML.T0061` · `MCP02` · `LLM01`

MCP tool definitions may contain malicious instructions designed to cause the LLM to replicate the prompt in its output. This self-replicating behavior allows the payload to propagate across connected systems and persist indefinitely. Such prompts are often combined with jailbreaks or data exfiltration directives.

**Remediation:** (1) Implement generative AI guardrails to filter and validate tool outputs for self-replicating patterns. (2) Enforce strict prompt guidelines that explicitly forbid outputting or propagating system instructions. (3) Align and fine-tune models to resist prompt replication and maintain safety boundaries. (4) Monitor tool definitions for hidden Unicode or unusually long instruction blocks.

**Tags:** `prompt-self-replication` `persistence` `static` `tool-poisoning`

---

### Llm Safety

#### MCPS-058 · Unverified Entity Generation Enabling Hallucination Discovery

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.packages`

**Maps to:** `AML.T0062` · `MCP08`

MCP tool definitions that instruct the LLM to generate software packages, URLs, or commands without explicit validation increase the risk of hallucination exploitation. Adversaries can leverage these hallucinated entities to publish malicious counterparts, leading to supply chain compromise or unauthorized access. This rule detects prompts and schema configurations that lack guardrails against fabricated outputs.

**Remediation:** (1) Implement generative AI guardrails to validate all LLM-generated entities against trusted registries. (2) Enforce strict input/output guidelines that prohibit unverified package or URL generation. (3) Pin all server dependencies to specific versions and hashes. (4) Apply model alignment techniques to reduce hallucination rates.

**Tags:** `hallucination` `llm-safety` `supply-chain` `static`

---

### Discovery

#### MCPS-060 · LLM System Information Discovery via Tool Definitions

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.name`, `tool.description`, `tool.annotations`

**Maps to:** `AML.T0069` · `LLM06`

MCP server definitions may include tools or resources designed to extract or reveal the LLM's system prompt, configuration, or internal instructions. Adversaries leverage these introspection capabilities to map system boundaries and craft targeted attacks.

**Remediation:** (1) Remove or restrict introspection tools in production MCP servers. (2) Validate tool names and descriptions against a denylist of system-extraction keywords. (3) Implement runtime guards to prevent tools from returning system prompts or configuration data.

**Tags:** `discovery` `system-prompt-leakage` `static` `introspection`

---

### Resource Abuse

#### MCPS-061 · Chaff Data Spamming via Tool Definitions

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`

**Maps to:** `AML.T0046` · `MCP02`

MCP tool definitions may be crafted to generate excessive low-value outputs or trigger high volumes of auditable events. This chaff data overwhelms AI agents and human reviewers, degrading system performance and wasting operational resources.

**Remediation:** (1) Implement rate limiting and query quotas for all MCP tool invocations. (2) Enforce authentication and identity verification for production model access. (3) Validate tool input schemas to enforce strict length and array size constraints. (4) Monitor and filter low-severity auditable events to prevent review fatigue.

**Tags:** `chaff-data` `agent-spam` `static` `impact`

---

#### MCPS-140 · Agentic Resource Consumption via Tool Directives

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `AML.T0034.002` · `MCP02`

MCP tool definitions may contain embedded directives that coerce AI agents into performing computationally expensive operations, excessive API calls, or recursive self-delegation loops. These patterns waste infrastructure resources, exhaust API budgets, and can lead to system stalls or denial of service.

**Remediation:** (1) Audit tool descriptions and annotations for directives encouraging excessive repetition, broad data fetching, or recursive calls. (2) Implement rate limiting and cost caps on agent tool invocations. (3) Enforce strict input validation and sandboxing to prevent self-delegation loops.

**Tags:** `resource-abuse` `denial-of-service` `agent-exploitation` `static`

---

#### MCPS-143 · Cost Harvesting via Unbounded Tool Execution

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `tool.annotations`

**Maps to:** `AML.T0034` · `LLM07`

MCP tool definitions may contain instructions or schema configurations that enable unbounded recursion, excessive iterations, or resource-intensive operations. Adversaries exploit these to inflate API costs and trigger autoscaling or service degradation in pay-per-use AI environments.

**Remediation:** (1) Implement strict rate limiting and query quotas per user and tool. (2) Enforce maximum token and output limits in tool input schemas. (3) Require authentication and monitor API usage for anomalous cost spikes. (4) Validate tool definitions against unbounded execution patterns before deployment.

**Tags:** `cost-harvesting` `resource-exhaustion` `static` `impact`

---

### Attack Staging

#### MCPS-062 · MCP Tool Attack Verification and Probing

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `server.env.*`, `tool.inputSchema`

**Maps to:** `AML.T0042` · `SEC.02`

Adversaries configure MCP tools or server endpoints to verify the efficacy of adversarial inputs or evasion techniques against target models. These definitions often include probing utilities, unbounded query capabilities, or metadata indicating robustness testing, enabling attackers to validate exploits before full deployment.

**Remediation:** (1) Implement passive output obfuscation to reduce model fidelity for probing. (2) Enforce strict rate limiting and query quotas on inference endpoints. (3) Restrict access to model registries and production APIs using strong authentication. (4) Monitor and audit tool invocation patterns for anomalous verification behavior.

**Tags:** `attack-staging` `model-probing` `static` `adversarial-testing`

---

### Prompt Security

#### MCPS-063 · System Prompt Exposure in MCP Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `server.env.*`

**Maps to:** `AML.T0069.002` · `LLM01` · `MCP02`

MCP server definitions may inadvertently expose system prompts, guardrails, or internal instruction sets within tool descriptions, annotations, or environment configurations. Adversaries can harvest these to understand model constraints and craft targeted prompt injection attacks to bypass safety mechanisms.

**Remediation:** (1) Remove system instructions and guardrail details from public-facing MCP definition fields. (2) Store prompt templates and system roles in secure, server-side configuration only. (3) Implement strict schema validation to prevent metadata leakage. (4) Regularly audit tool descriptions and annotations for sensitive context.

**Tags:** `system-prompt` `information-disclosure` `static` `guardrail-bypass`

---

### Infrastructure Integrity

#### MCPS-064 · Detection of Unauthorized AI Service Proxy Endpoints

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.url`, `server.transport`, `server.env.*`

**Maps to:** `AML.T0008.005` · `MCP08` · `LLM06`

MCP server definitions may route AI requests through unauthorized third-party proxy services instead of official provider endpoints. These proxies often resell access using compromised credentials or bulk accounts, enabling model distillation, credential theft, and traffic obfuscation. Static analysis can identify suspicious URL patterns and routing configurations indicative of proxy infrastructure.

**Remediation:** (1) Verify all server URLs and transport endpoints resolve to official AI provider domains. (2) Implement strict allowlisting for approved API gateways and reject third-party proxy routing. (3) Rotate API credentials immediately if proxy indicators are detected. (4) Monitor traffic patterns for bulk account usage or credential sharing signatures.

**Tags:** `proxy-detection` `llm-jacking` `static` `infrastructure-integrity`

---

### Credential Exposure

#### MCPS-066 · Hardcoded Credentials in MCP Server Definition

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.env.*`, `tool.inputSchema`, `server.url`

**Maps to:** `AML.T0012` · `MCP01`

MCP server definitions may inadvertently expose hardcoded credentials, API keys, or authentication tokens within environment variables, tool schemas, or server URLs. Adversaries can harvest these valid accounts to gain unauthorized initial access to AI resources, models, or backend services.

**Remediation:** (1) Remove hardcoded credentials from MCP definitions. (2) Use environment variable injection or secret management systems. (3) Enforce authentication constraints in tool schemas. (4) Audit server URLs for embedded credentials.

**Tags:** `credential-exposure` `valid-accounts` `static` `initial-access`

---

#### MCPS-099 · Hardcoded Credentials in MCP Server Definition

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.env.*`, `server.url`, `tool.inputSchema`

**Maps to:** `AML.T0055` · `MCP04`

MCP server definition files may inadvertently contain hardcoded credentials, API keys, or authentication tokens within environment variables, URLs, or tool schemas. Static analysis detects these insecure storage practices to prevent credential leakage during deployment or version control. Exposed secrets can be harvested by adversaries to gain unauthorized access to backend services.

**Remediation:** (1) Remove hardcoded credentials from definition files. (2) Use environment variable injection or secret management systems. (3) Enforce TLS for all server communications. (4) Validate tool schemas to reject credential inputs at runtime.

**Tags:** `credential-exposure` `hardcoded-secrets` `static` `configuration`

---

### Ai Safety

#### MCPS-068 · Detects Tools Capable of Generating Deepfakes

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `tool.inputSchema`

**Maps to:** `AML.T0088`

MCP servers may expose tools that leverage generative AI to create synthetic media, including deepfakes, face swaps, or voice clones. These capabilities can be weaponized for identity fraud, KYC bypass, or biometric evasion. Static analysis scans tool metadata for indicators of synthetic media generation.

**Remediation:** (1) Apply deepfake detection algorithms to all tool-generated or user-provided media. (2) Incorporate multi-modal sensors and liveness checks to verify authenticity. (3) Restrict access to generative media tools to authorized personnel only. (4) Audit tool definitions for synthetic media capabilities.

**Tags:** `deepfake` `ai-safety` `biometric-evasion` `static`

---

### Input Validation

#### MCPS-069 · Unbounded Input Schema Enables Resource Exhaustion

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.inputSchema`, `tool.description`

**Maps to:** `AML.T0034.001` · `LLM06`

MCP tool definitions that lack input constraints can be exploited to submit resource-intensive queries. Adversaries may craft oversized strings, deeply nested structures, or prompts demanding complex reasoning to exhaust compute resources and increase latency. Static analysis of the input schema and tool metadata helps identify these vulnerabilities before deployment.

**Remediation:** (1) Enforce maxLength and maxItems constraints in tool input schemas. (2) Implement server-side token and compute limits per request. (3) Validate and sanitize tool descriptions to avoid encouraging unbounded reasoning or output generation. (4) Monitor API latency and resource consumption for anomalous spikes.

**Tags:** `resource-exhaustion` `schema-validation` `static` `denial-of-service`

---

#### MCPS-081 · Adversarial Data Crafting via Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `tool.annotations`

**Maps to:** `AML.T0043` · `MCP02` · `PR.AN-03`

MCP tool definitions may contain adversarial payloads or lack input validation, enabling attackers to craft data that evades model safety filters or triggers unintended behaviors. This technique targets the staging phase where malicious inputs are embedded in tool metadata or schemas before execution.

**Remediation:** (1) Validate AI models for backdoor triggers and adversarial influence. (2) Implement model hardening via adversarial training or network distillation. (3) Restrict the number and rate of AI model queries. (4) Use ensemble methods to increase robustness against adversarial inputs. (5) Apply passive AI output obfuscation to reduce information leakage.

**Tags:** `adversarial-data` `input-validation` `static` `ai-security`

---

#### MCPS-112 · Adversarial Input Crafting via Unconstrained Tool Schemas

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.inputSchema`, `tool.description`

**Maps to:** `AML.T0043.003` · `MCP04`

MCP tool definitions that lack strict input constraints allow adversaries to manually modify and craft adversarial inputs. By exploiting overly permissive schemas, attackers can iteratively tweak parameters to bypass model safeguards or trigger unintended behaviors.

**Remediation:** (1) Implement input restoration and sanitization pipelines to nullify adversarial perturbations. (2) Apply model hardening techniques such as adversarial training or ensemble methods. (3) Restrict query rates and enforce strict schema validation with maxLength and pattern constraints. (4) Deploy adversarial input detection algorithms to block atypical queries.

**Tags:** `adversarial-input` `manual-modification` `input-validation` `static`

---

### Ai Media Safety

#### MCPS-070 · Deepfake Phishing Facilitation via MCP Tools

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `tool.inputSchema`, `server.url`

**Maps to:** `AML.T0052.001` · `AGT04` · `PR.USA.1`

MCP server definitions may expose tools designed to generate synthetic media or clone voices for phishing campaigns. These tools often advertise capabilities like voice cloning, deepfake generation, or executive impersonation in their metadata. Static analysis can identify malicious tool configurations that accept sensitive audio/video inputs or reference untrusted AI synthesis endpoints.

**Remediation:** (1) Audit tool descriptions and input schemas for synthetic media generation capabilities. (2) Restrict access to AI voice/video cloning endpoints. (3) Implement strict input validation and size limits for media uploads. (4) Deploy AI content provenance verification before processing.

**Tags:** `deepfake` `phishing` `ai-media` `static` `social-engineering`

---

### Ai Attack Staging

#### MCPS-071 · MCP Server Proxy Model Staging Detection

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.inputSchema`, `server.env.*`, `server.url`

**Maps to:** `AML.T0005` · `LLM06`

MCP server definitions may be configured to route inference requests through locally hosted or offline proxy models. Adversaries leverage these configurations to simulate target model behavior, bypass rate limits, or stage evasion attacks without direct access to production APIs. This staging enables offline adversarial training and model replication.

**Remediation:** (1) Restrict public release of model artifacts and stack details. (2) Enforce authentication and rate limiting on all model endpoints. (3) Validate and allowlist backend model URLs to prevent unauthorized proxy routing. (4) Implement output obfuscation to hinder model replication.

**Tags:** `proxy-model` `ai-staging` `static` `model-replication`

---

### Model Integrity

#### MCPS-072 · Model Poisoning via Unverified Weights and Data

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `server.env.*`, `server.packages[]`

**Maps to:** `AML.T0018.000` · `MCP08` · `LLM06`

MCP servers may reference external AI models or datasets without integrity verification. Adversaries can poison model weights or training data to alter agent behavior, inject backdoors, or degrade performance. This rule detects unverified model references, disabled integrity checks, and missing provenance constraints in server definitions.

**Remediation:** (1) Enforce cryptographic signing and verification of all model weights and datasets. (2) Sanitize and validate training data prior to ingestion to remove poisoned samples. (3) Maintain strict dataset provenance records and monitor for concept drift. (4) Restrict access to model registries and enforce least-privilege controls on production models.

**Tags:** `model-poisoning` `supply-chain` `integrity` `static`

---

#### MCPS-091 · Model Extraction via Unrestricted Query Tools

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `tool.inputSchema`, `server.env.*`

**Maps to:** `AML.T0024.002` · `LLM06`

MCP server definitions may expose tools that facilitate model extraction or distillation by allowing unrestricted querying, exposing raw model outputs, or lacking rate limiting and telemetry. Adversaries leverage these configurations to collect inference data for training surrogate models offline.

**Remediation:** (1) Implement passive output obfuscation to reduce inference fidelity. (2) Enforce strict rate limits and query quotas per user or session. (3) Enable comprehensive AI telemetry logging for inputs, outputs, and agent steps. (4) Monitor for anomalous query patterns indicative of distillation campaigns.

**Tags:** `model-extraction` `distillation` `rate-limiting` `static`

---

#### MCPS-101 · MCP Tool Schema Lacks Adversarial Input Guards

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.inputSchema`, `tool.description`

**Maps to:** `AML.T0031` · `LLM08`

MCP tool definitions that lack strict input constraints or sanitization directives can be exploited to feed adversarial examples to the underlying model. Over time, these inputs degrade model performance and erode system reliability, aligning with data poisoning and adversarial attack vectors. This static analysis identifies configurations that leave the inference pipeline vulnerable to integrity erosion.

**Remediation:** (1) Implement input restoration and sanitization preprocessing for all tool inputs. (2) Enforce strict schema constraints (maxLength, pattern, format) to block adversarial perturbations. (3) Deploy adversarial input detection algorithms prior to model inference. (4) Utilize ensemble methods or hardened models to increase robustness against poisoning and degradation attacks.

**Tags:** `model-integrity` `adversarial-input` `data-poisoning` `static`

---

#### MCPS-105 · Adversarial AI Attack Vector Detection

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `tool.inputSchema`

**Maps to:** `AML.T0017.000` · `RMF-05`

MCP tool definitions may be crafted to function as adversarial attack vectors against downstream AI models. This rule detects metadata referencing evasion techniques, bypass strings, or backdoor triggers that could compromise model robustness.

**Remediation:** (1) Audit tool descriptions and schemas for adversarial terminology. (2) Implement input sanitization and robustness testing for model interactions. (3) Restrict tool capabilities to prevent bypass attempts. (4) Monitor for anomalous model behavior indicative of adversarial inputs.

**Tags:** `adversarial-ai` `model-robustness` `static` `evasion`

---

#### MCPS-109 · Model Manipulation and Weight Poisoning Detection

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.packages[]`, `server.url`, `tool.inputSchema`

**Maps to:** `AML.T0018` · `MCP08` · `LLM06`

MCP server definitions may reference compromised AI models, poisoned weights, or modified architectures that persist malicious behavior. Adversaries exploit unvalidated model sources to embed backdoors or alter inference logic without detection. This technique covers weight poisoning, architecture modification, and embedded malware within model artifacts.

**Remediation:** (1) Enforce cryptographic signing and verification of all model artifacts and weights. (2) Validate model integrity against known-good baselines before deployment. (3) Restrict access to model registries and training data to authorized personnel only. (4) Monitor for concept drift and anomalous inference patterns indicating poisoning.

**Tags:** `model-poisoning` `supply-chain` `static` `persistence`

---

### Agent Permissions

#### MCPS-073 · Overly Permissive Local Agent Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `tool.inputSchema`

**Maps to:** `AML.T0112.000` · `MCP02` · `LLM01`

MCP tool definitions that grant direct operating system access, command execution, or unrestricted file system permissions enable local AI agent abuse. When agents invoke these tools without sandboxing or strict permission scopes, adversaries can achieve remote code execution, data exfiltration, and full host compromise.

**Remediation:** (1) Restrict tool capabilities to specific, audited functions rather than raw shell access. (2) Enforce strict input validation and length limits on command or script parameters. (3) Declare explicit permission scopes and sandbox boundaries in tool definitions. (4) Implement runtime execution contexts that isolate agent actions from the host OS.

**Tags:** `local-agent` `over-permission` `rce-risk` `static` `sandboxing`

---

### System Enumeration

#### MCPS-074 · Unrestricted Process Enumeration Tool

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `tool.inputSchema`

**Maps to:** `AML.T0089` · `MCP05`

MCP tools that expose system process enumeration capabilities can be abused by adversaries for reconnaissance. Identifying running AI applications and their associated tokens facilitates credential access and lateral movement. Unrestricted access to process lists increases the attack surface for memory scraping and token theft.

**Remediation:** (1) Restrict tool capabilities to prevent unrestricted system enumeration. (2) Implement sandboxing for command execution tools. (3) Audit tool definitions for reconnaissance capabilities. (4) Apply least-privilege principles to MCP server processes.

**Tags:** `process-discovery` `reconnaissance` `static` `tool-capability`

---

### Adversarial Robustness

#### MCPS-075 · Black-Box Transfer via Adversarial Input Crafting

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `tool.annotations`

**Maps to:** `AML.T0043.002` · `LLM06`

MCP server definitions may expose tools or configurations that facilitate black-box transfer attacks. Adversaries craft adversarial inputs optimized against proxy models to evade detection or manipulate the target LLM. Static analysis detects indicators of transfer attack preparation, unhardened input schemas, and proxy model references.

**Remediation:** (1) Implement model hardening techniques such as adversarial training or network distillation. (2) Use ensemble methods for inference to increase robustness against transfer attacks. (3) Preprocess all inference data to nullify or reverse potential adversarial perturbations. (4) Incorporate adversarial detection algorithms to block atypical queries and malicious inputs.

**Tags:** `black-box-transfer` `adversarial-inputs` `static` `model-robustness`

---

### Artifact Integrity

#### MCPS-076 · Unsafe AI Artifact Loading via Serialization

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.packages[]`, `server.url`, `tool.inputSchema`

**Maps to:** `AML.T0011.000` · `MCP08`

MCP server definitions may reference or load AI artifacts using unsafe serialization formats like pickle or joblib. Without integrity verification, these artifacts can execute arbitrary code or establish persistent access when deserialized by the host environment.

**Remediation:** (1) Restrict library loading mechanisms and validate all AI artifacts before execution. (2) Enforce cryptographic signing and checksum verification for all models and dependencies. (3) Scan artifacts for unsafe serialization formats like pickle. (4) Educate developers on AI supply chain risks and safe deserialization practices.

**Tags:** `unsafe-artifacts` `deserialization` `supply-chain` `static`

---

### Api Abuse

#### MCPS-077 · Unrestricted API Querying for Black-Box Optimization

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.env.*`, `tool.inputSchema`, `tool.description`

**Maps to:** `AML.T0043.001` · `MCP02`

Black-box optimization attacks rely on iterative queries to an AI model API to refine adversarial inputs. MCP servers lacking rate limits, input validation, or output obfuscation facilitate these attacks by allowing unbounded probing and direct model feedback.

**Remediation:** (1) Enforce strict rate limits and query caps on all model endpoints. (2) Apply passive output obfuscation to reduce model fidelity leakage. (3) Validate and constrain all tool inputs to prevent iterative mutation. (4) Monitor API logs for high-frequency probing patterns.

**Tags:** `black-box` `api-abuse` `rate-limiting` `static`

---

### Privilege Escalation

#### MCPS-078 · Host Escape via Disabled Safety Controls

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.annotations`, `tool.inputSchema`, `server.env.*`

**Maps to:** `AML.T0105` · `MCP02` · `PR.AA-03`

MCP server definitions may contain configurations that disable safety guardrails or sandboxing mechanisms, allowing AI agents to execute tools directly on the host environment. This technique detects patterns indicating the removal of execution restrictions or explicit host-level access permissions. Such misconfigurations can lead to remote code execution and full host compromise.

**Remediation:** (1) Enforce mandatory sandboxing for all tool executions. (2) Validate and restrict environment variables that modify execution contexts. (3) Implement strict allowlists for host-level operations. (4) Audit tool definitions for disabled safety controls.

**Tags:** `privilege-escalation` `host-escape` `sandbox-bypass` `static`

---

### Ai Evasion

#### MCPS-079 · Adversarial Evasion Triggers in MCP Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `server.url`

**Maps to:** `AML.T0015`

MCP server and tool definitions may contain adversarial perturbations, bypass strings, or mutated domain patterns designed to evade AI-based security scanners or content filters. These payloads are embedded in metadata to trick downstream AI models into misclassifying malicious tools or resources as benign.

**Remediation:** (1) Implement adversarial input detection algorithms to block atypical queries. (2) Preprocess inference data to nullify adversarial perturbations. (3) Deploy ensemble methods and multi-modal sensors to increase robustness. (4) Apply model hardening techniques such as adversarial training.

**Tags:** `ai-evasion` `adversarial-input` `static` `initial-access`

---

### Identity Impersonation

#### MCPS-080 · MCP Tool Impersonation via Deceptive Metadata

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `server.url`

**Maps to:** `AML.T0073` · `MCP08`

MCP tool and server definitions may contain deceptive metadata claiming affiliation with trusted organizations, internal teams, or executive approval. Adversaries use these impersonation signals to bypass LLM safety filters or trick users into granting excessive permissions to malicious tools.

**Remediation:** (1) Verify publisher identity via cryptographic signatures. (2) Cross-reference tool names and descriptions against known vendor registries. (3) Enforce strict naming conventions and reject claims of official status in unverified definitions. (4) Implement allowlisting for trusted MCP server sources.

**Tags:** `impersonation` `supply-chain` `static` `defense-evasion`

---

### Agent Manipulation

#### MCPS-084 · Deceptive Agent Baiting via Tool Metadata

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `server.url`

**Maps to:** `AML.T0100` · `MCP02`

MCP tool definitions and server URLs may contain deceptive language or links designed to manipulate AI agents into performing unintended actions. These patterns exploit the agent's reliance on metadata for context, potentially leading to unauthorized command execution or data exfiltration.

**Remediation:** (1) Audit tool descriptions and annotations for social engineering language. (2) Implement strict content validation and allowlisting for server URLs. (3) Deploy agent-side guardrails to verify metadata before execution. (4) Educate developers on clickbait patterns targeting AI agents.

**Tags:** `agent-manipulation` `clickbait` `social-engineering` `static`

---

### Url Integrity

#### MCPS-085 · Malicious Link Execution in MCP Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.url`, `tool.description`, `tool.inputSchema`

**Maps to:** `AML.T0011.003` · `MCP04`

MCP server and tool definitions may contain hardcoded URLs or links that point to malicious payloads or exploit scripts. When an AI agent automatically follows these links without proper origin validation or sandboxing, it can lead to remote code execution or unauthorized data exfiltration. This technique exploits the agent's trust in predefined connection endpoints.

**Remediation:** (1) Validate and sanitize all URLs in MCP definitions against a strict allowlist. (2) Disable automatic link following or require explicit user confirmation before fetching external resources. (3) Implement origin validation and sandboxing for all outbound agent requests. (4) Scan definitions for dangerous URI schemes and execution parameters.

**Tags:** `malicious-link` `rce` `url-validation` `static`

---

### Supply Chain Trust

#### MCPS-086 · Reputation Inflation via Fabricated Trust Signals

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `server.url`, `server.packages[]`

**Maps to:** `AML.T0111` · `MCP08`

Adversaries embed fabricated trust signals, fake endorsements, or inflated adoption metrics in MCP tool and server definitions to appear legitimate. These deceptive metadata claims bypass human and automated trust checks, increasing the likelihood of adoption before malicious updates are deployed.

**Remediation:** (1) Verify publisher identity through cryptographic signatures or official registry attestations. (2) Cross-reference claimed endorsements and metrics with authoritative sources. (3) Implement strict allowlisting for MCP components and avoid relying on self-reported trust signals. (4) Monitor for sudden changes in component behavior after initial adoption.

**Tags:** `supply-chain` `reputation-inflation` `defense-evasion` `static`

---

### Model Extraction

#### MCPS-087 · Model Replication via Unrestricted Inference Tools

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.url`

**Maps to:** `AML.T0005.001` · `PR.AIML-1`

MCP server definitions exposing model inference capabilities without rate limiting or output obfuscation enable adversaries to systematically query the API. Collected input-output pairs can train a surrogate model that replicates the target's behavior, facilitating downstream evasion or adversarial attacks.

**Remediation:** (1) Implement rate limiting and query quotas on all inference endpoints. (2) Apply output obfuscation or truncation to reduce model fidelity leakage. (3) Enable comprehensive AI telemetry logging to detect systematic probing patterns. (4) Restrict access to model APIs using authentication and allowlisting.

**Tags:** `model-replication` `surrogate-training` `rate-limiting` `static`

---

### Ai Ip Theft

#### MCPS-088 · AI Model and Dataset Exfiltration via MCP Tools

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.url`

**Maps to:** `AML.T0048.004` · `LLM06` · `MCP05`

MCP server definitions may expose tools or resources that facilitate the unauthorized extraction of proprietary AI models, training datasets, or API credentials. Adversaries leverage these exposed interfaces to replicate models or dump sensitive training data, causing significant economic harm and intellectual property loss.

**Remediation:** (1) Implement strict access controls on model registries and training datasets. (2) Encrypt AI artifacts at rest and in transit. (3) Serve models via secure cloud APIs rather than exposing local files or direct download endpoints. (4) Monitor and rate-limit AI service API usage to prevent unauthorized replication.

**Tags:** `ai-ip-theft` `model-exfiltration` `static` `data-leak`

---

### System Integrity

#### MCPS-090 · MCP Server Machine Compromise via Tool Execution

**Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.packages[]`

**Maps to:** `AML.T0112` · `MCP08`

MCP server definitions may expose tools or dependencies that allow arbitrary code execution or payload delivery on the host machine. Adversaries exploit unrestricted input schemas or compromised packages to gain system-level access and persist. Static analysis identifies dangerous command references and missing validation constraints before deployment.

**Remediation:** (1) Restrict tool capabilities to read-only or sandboxed environments. (2) Enforce strict input validation and schema constraints on all command parameters. (3) Pin all server dependencies to specific, verified versions. (4) Implement runtime execution policies to block unauthorized system calls.

**Tags:** `machine-compromise` `arbitrary-code-execution` `supply-chain` `static`

---

### Model Artifact Exposure

#### MCPS-094 · Model Artifact Exposure in MCP Definitions

**Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.env.*`, `server.packages[]`

**Maps to:** `AML.T0002.001` · `MCP08`

MCP server definitions may inadvertently expose references to model artifacts, configuration files, or training checkpoints. Adversaries can harvest these references to replicate victim models, tailor adversarial attacks, or inject backdoors into the AI pipeline.

**Remediation:** (1) Limit public release of model artifacts and technical details. (2) Verify cryptographic checksums of all AI artifacts. (3) Remove hardcoded model paths and weights from MCP definitions. (4) Use environment variables or secure vaults for sensitive model references.

**Tags:** `model-exposure` `artifact-leak` `supply-chain` `static`

---

### Execution Control

#### MCPS-095 · User Execution via Unsafe MCP Artifacts

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.packages[]`, `server.url`

**Maps to:** `AML.T0011` · `MCP08`

MCP server definitions may contain references to unverified packages, unsafe artifacts, or malicious links that rely on user interaction to trigger execution. Adversaries embed these elements to trick users or agents into loading compromised code or visiting phishing endpoints. Static analysis can identify suspicious execution triggers and untrusted resource references before deployment.

**Remediation:** (1) Verify cryptographic checksums of all AI artifacts and packages. (2) Restrict library loading and disable unsafe deserialization formats like pickle. (3) Maintain an AI Bill of Materials to track provenance. (4) Educate users on identifying malicious links and social engineering attempts. (5) Scan server definitions for untrusted execution triggers before deployment.

**Tags:** `user-execution` `supply-chain` `static` `malicious-links`

---

### Data Exfiltration

#### MCPS-096 · Exfiltration via Unrestricted AI Inference API

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.url`, `server.env.*`

**Maps to:** `AML.T0024` · `LLM06`

MCP server definitions may configure tools or transports that route sensitive data to external AI inference APIs without proper safeguards. Adversaries can exploit these configurations to exfiltrate private training data, invert models, or extract model weights through excessive or unauthenticated queries. This technique highlights the risk of unmonitored inference endpoints in agentic workflows.

**Remediation:** (1) Restrict the number and rate of AI model queries via rate limiting. (2) Enforce strict authentication and access controls for all inference API endpoints. (3) Implement comprehensive telemetry logging for model inputs, outputs, and agent actions to detect anomalous exfiltration attempts. (4) Validate and sanitize all data sent to external AI services.

**Tags:** `data-exfiltration` `model-inversion` `api-security` `static`

---

#### MCPS-115 · Data Exfiltration via External Endpoints

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `server.url`, `tool.inputSchema`

**Maps to:** `AML.T0025` · `MCP06`

MCP server and tool definitions may be configured to route sensitive AI artifacts, conversation context, or model outputs to untrusted external endpoints. This pattern detects configurations that facilitate unauthorized data transmission or exfiltration via traditional cyber means.

**Remediation:** (1) Establish strict access controls on internal model registries and limit production model access to approved users. (2) Validate and allowlist all external server URLs and data endpoints. (3) Enforce schema constraints on tool outputs to prevent arbitrary data transmission. (4) Monitor network traffic for unauthorized data transfers.

**Tags:** `exfiltration` `data-leak` `external-endpoints` `static`

---

#### MCPS-029 · Covert Data Exfiltration via Rendered Image URLs

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `AML.T0077` · `LLM06`

MCP tool definitions and annotations may contain markdown or HTML image tags designed to exfiltrate sensitive data when rendered by the client. Adversaries embed query parameters in image URLs that automatically transmit conversation context or private information to external servers upon rendering.

**Remediation:** (1) Sanitize all markdown and HTML in tool descriptions and annotations. (2) Block automatic rendering of external image URLs in MCP clients. (3) Implement strict output filtering to strip query parameters from rendered media. (4) Audit tool definitions for exfiltration keywords in URL parameters.

**Tags:** `data-exfiltration` `rendering-injection` `static` `markdown`

---

#### MCPS-134 · Data Exfiltration via Tool Input Parameters

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.inputSchema`, `tool.description`

**Maps to:** `AML.T0086` · `MCP02`

MCP tool definitions that accept unvalidated input parameters or expose write and network capabilities can be abused to exfiltrate sensitive data. Adversaries may manipulate tool inputs via prompt injection or malicious definitions to transmit information to external endpoints, email inboxes, or cloud storage under the guise of legitimate operations.

**Remediation:** (1) Implement comprehensive AI telemetry logging for all tool inputs and outputs. (2) Enforce strict least-privilege permissions and validate tool capabilities against organizational policy. (3) Require human-in-the-loop approval for sensitive write or network operations. (4) Apply strict input validation and allowlisting for all tool parameters to prevent data leakage.

**Tags:** `exfiltration` `tool-invocation` `static` `data-leakage`

---

### Model Inversion

#### MCPS-097 · Model Inversion via Confidence Score Exposure

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`

**Maps to:** `AML.T0024.001`

MCP server definitions that expose model confidence scores, raw probabilities, or lack query rate limits can enable model inversion attacks. Adversaries strategically query the inference API to reconstruct sensitive training data or private features. This rule flags configurations that inadvertently leak high-fidelity model outputs or permit unbounded querying.

**Remediation:** (1) Apply passive output obfuscation to reduce fidelity of confidence scores and raw outputs. (2) Enforce strict rate limits and query budgets per user or session. (3) Implement comprehensive AI telemetry logging to monitor and detect anomalous querying patterns.

**Tags:** `model-inversion` `data-privacy` `static` `confidence-leak`

---

### Data Collection

#### MCPS-102 · Unrestricted Repository Data Access in MCP Tools

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.env.*`

**Maps to:** `AML.T0036` · `MCP04`

MCP tools configured to query or scrape information repositories may expose sensitive organizational data to AI agents. Without strict input validation, authentication requirements, or data filtering, these tools can be abused to mass-collect credentials, source code, or proprietary documents. This aligns with adversary techniques that leverage misconfigured repositories for large-scale data collection.

**Remediation:** (1) Enforce strict authentication and authorization checks in tool input schemas. (2) Implement query limits and data filtering to prevent bulk exfiltration. (3) Audit repository connection configurations for hardcoded credentials or overly permissive access. (4) Log and monitor all repository access initiated by AI agents.

**Tags:** `data-collection` `repository-access` `static` `aml-t0036`

---

### Trigger Control

#### MCPS-104 · Uncontrolled MCP Tool Activation Triggers

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `AML.T0084.002` · `MCP02`

MCP tool definitions may declare automatic activation triggers or event listeners that execute without explicit user confirmation. Adversaries can exploit overly broad or undocumented triggers to initiate unintended agent workflows, potentially leading to data exfiltration or unauthorized system actions.

**Remediation:** (1) Explicitly define and constrain trigger conditions in tool annotations. (2) Require explicit user confirmation for event-driven tool execution. (3) Audit tool descriptions for automatic activation claims and remove undocumented triggers. (4) Implement allowlists for permitted trigger sources.

**Tags:** `activation-triggers` `event-driven` `static` `agent-control`

---

### Model Supply Chain

#### MCPS-106 · Compromised Model Loading via Untrusted Dependencies

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.packages[]`, `server.url`

**Maps to:** `AML.T0010.003` · `MCP08` · `RMF-1.1`

MCP server definitions may reference external AI models or packages for inference and fine-tuning. Adversaries compromise these model artifacts with backdoors or malicious code, which execute when the server loads them. This rule detects unversioned references and missing integrity constraints in model dependencies.

**Remediation:** (1) Enforce cryptographic signing and verification for all model artifacts and dependencies. (2) Pin exact versions and checksums for all external model references. (3) Validate models in isolated sandboxes before loading into production MCP servers. (4) Restrict model loading to approved internal registries.

**Tags:** `model-supply-chain` `dependency-verification` `static` `integrity`

---

### Ai Model Access

#### MCPS-107 · Indirect AI Model Access via Third-Party Service

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `server.url`, `tool.inputSchema`

**Maps to:** `AML.T0047` · `LLM08` · `PR.AIML-3`

MCP tool and server definitions may integrate external AI-enabled products or services that expose underlying model inference endpoints. Without proper isolation, telemetry, or input validation, these integrations can leak model details, enable indirect model access, or facilitate evasion attacks against AI security controls.

**Remediation:** (1) Implement comprehensive AI telemetry logging for all model inputs, outputs, and intermediate agentic steps. (2) Enforce strict input validation and rate limiting on tools interacting with external AI services. (3) Isolate third-party AI integrations using sandboxed execution environments. (4) Audit and verify the security posture of all AI-enabled dependencies before deployment.

**Tags:** `ai-model-access` `telemetry` `third-party-ai` `static`

---

### Supply Chain Security

#### MCPS-110 · Adversarial AI Library Dependency Detection

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.packages[]`, `tool.description`, `tool.annotations`

**Maps to:** `AML.T0016.000` · `MCP08`

MCP server definitions may declare dependencies on open-source adversarial AI attack frameworks. These libraries, originally intended for research, can be weaponized to generate evasion examples, poison training data, or bypass model safeguards within the agent's execution environment.

**Remediation:** (1) Audit server dependencies for research-only adversarial AI libraries. (2) Replace with production-hardened alternatives or remove if unnecessary. (3) Implement strict allowlisting for third-party packages. (4) Scan tool descriptions for unauthorized attack terminology.

**Tags:** `adversarial-ai` `supply-chain` `static` `dependency-audit`

---

### Artifact Exposure

#### MCPS-116 · AI Artifact Collection via MCP Exposure

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.url`, `server.env.*`

**Maps to:** `AML.T0035` · `MCP02`

MCP servers may inadvertently expose tools or resources that aggregate, download, or reference sensitive AI artifacts such as model checkpoints, training datasets, or internal telemetry. Adversaries can leverage these exposed endpoints to collect artifacts for exfiltration or offline model analysis. Static analysis identifies references to artifact storage and unrestricted data export capabilities.

**Remediation:** (1) Limit public release of model checkpoints and training datasets. (2) Enforce strict access controls and encryption on artifact storage endpoints. (3) Prefer cloud-hosted model serving over edge deployment to reduce exposure. (4) Validate and restrict tool capabilities that aggregate or export internal telemetry.

**Tags:** `artifact-collection` `data-exposure` `static` `model-security`

---

### Model Access Control

#### MCPS-118 · White-Box Model Access and Input Exposure

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.env.*`

**Maps to:** `AML.T0043.000` · `LLM06` · `MCP05`

White-box optimization attacks require direct access to model internals, gradients, or unfiltered input channels. This rule detects MCP tool or server definitions that expose model architecture, lack input validation constraints, or claim direct/raw model access, creating conditions for adversarial example generation.

**Remediation:** (1) Restrict direct access to model weights, gradients, and internal parameters. (2) Enforce strict input validation and sanitization on all tool schemas. (3) Implement adversarial input detection and restoration mechanisms. (4) Apply model hardening techniques and ensemble methods to increase robustness.

**Tags:** `white-box` `adversarial-ml` `input-validation` `static`

---

### Financial Security

#### MCPS-120 · Financial Fraud and Identity Bypass Detection

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `AML.T0048.000` · `MCP02`

MCP tools configured for financial operations or identity verification may be misused to facilitate fraud, unauthorized transactions, or verification bypass. This rule detects tool definitions containing language indicative of financial harm, identity spoofing, or control evasion.

**Remediation:** (1) Audit tool descriptions and annotations for financial fraud or identity bypass language. (2) Enforce strict authentication and authorization constraints on all financial or identity-related tools. (3) Implement transaction validation and anomaly detection for monetary operations. (4) Restrict tool access to verified, authorized users only.

**Tags:** `financial-fraud` `identity-bypass` `static` `mcp-security`

---

### User Harm

#### MCPS-121 · User Data Exfiltration and Harm via MCP Tools

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `AML.T0048.003` · `MCP02`

MCP tool definitions may contain hidden instructions or configurations that facilitate the exfiltration of personal data, conversation history, or financial information. These patterns often leverage indirect prompt injection vectors, such as rendering external URLs or suggesting unverified package installations, directly harming individual users rather than the host organization.

**Remediation:** (1) Audit tool descriptions and annotations for exfiltration or data collection instructions. (2) Enforce strict output filtering to block external URL rendering in user-facing responses. (3) Validate all package dependencies against trusted registries before execution. (4) Implement user consent prompts for any tool accessing personal or financial data.

**Tags:** `user-harm` `data-exfiltration` `prompt-injection` `static`

---

### Server Exposure

#### MCPS-122 · Exposed MCP Server Endpoint Without Authentication

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.url`, `server.transport`, `server.env.*`

**Maps to:** `AML.T0049` · `MCP01`

MCP server definitions may reference publicly accessible endpoints or cloud AI services without enforcing encryption or authentication. Adversaries exploit these exposed interfaces to intercept traffic, inject malicious payloads, or hijack model access. Static analysis identifies insecure transport protocols, direct IP bindings, and missing credential requirements in the configuration.

**Remediation:** (1) Enforce HTTPS/TLS for all server.url definitions. (2) Require authentication tokens or API keys in server.env or transport configuration. (3) Restrict network exposure using firewall rules or private VPC endpoints. (4) Validate and sign MCP server manifests before deployment.

**Tags:** `initial-access` `server-exposure` `insecure-transport` `static`

---

### Data Ingestion

#### MCPS-135 · Prompt Infiltration via Untrusted Data Ingestion

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.url`

**Maps to:** `AML.T0093` · `MCP02` · `LLM01`

MCP tools that ingest content from public-facing applications or untrusted external sources are vulnerable to indirect prompt infiltration. Malicious payloads embedded in emails, documents, or web pages can be processed by the tool and injected into the LLM context, potentially hijacking agent behavior or exfiltrating data.

**Remediation:** (1) Implement strict input validation and sanitization for all external data fields. (2) Enforce maxLength and pattern constraints in tool input schemas. (3) Isolate untrusted content processing from the main LLM context using sandboxed sub-agents. (4) Verify and authenticate all data source endpoints before ingestion.

**Tags:** `prompt-infiltration` `indirect-injection` `data-ingestion` `static`

---

### Configuration Integrity

#### MCPS-138 · AI Agent Configuration Tampering Detection

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `server.url`, `server.transport`

**Maps to:** `AML.T0081` · `MCP08` · `LLM01`

Adversaries modify MCP server definitions to alter AI agent configurations, system prompts, or security guardrails. These changes persist across sessions and can disable safety controls, redirect tool calls to malicious endpoints, or embed covert instructions for data exfiltration.

**Remediation:** (1) Validate and sign all MCP server definitions before deployment. (2) Enforce strict schema validation to reject unauthorized configuration overrides. (3) Scan definition files for invisible Unicode and prompt injection patterns. (4) Implement allowlists for server endpoints and tool configurations. (5) Enable human-in-the-loop approval for configuration changes.

**Tags:** `configuration-tampering` `persistence` `static` `guardrail-bypass`

---

### Configuration Exposure

#### MCPS-139 · Exposed AI Agent Configuration and Secrets

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.env.*`, `tool.description`, `tool.annotations`, `server.transport`

**Maps to:** `AML.T0002.002` · `MCP01` · `LLM01`

MCP server definition files may inadvertently expose sensitive configuration details, hardcoded credentials, or dynamic loading mechanisms. If these files are publicly accessible or leaked, adversaries can map agent capabilities, harvest secrets, or inject malicious system prompts to hijack agent behavior.

**Remediation:** (1) Remove hardcoded secrets and use secure secret management. (2) Restrict configuration file access with strict permissions. (3) Validate and sanitize all external configuration references. (4) Enforce TLS and authentication for all server transports.

**Tags:** `config-exposure` `secret-leakage` `prompt-injection` `static`

---

### Memory Integrity

#### MCPS-141 · Persistent Memory Manipulation via MCP Tools

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.env.*`

**Maps to:** `AML.T0080.000` · `LLM02` · `MCP02`

MCP server definitions may expose tools or configurations that allow untrusted data to be written directly to persistent memory or context stores. Adversaries exploit these pathways to inject malicious instructions or false facts that persist across sessions, effectively poisoning the LLM's long-term memory and altering future agent behavior.

**Remediation:** (1) Implement memory hardening by enforcing strict trust boundaries for all context storage. (2) Require explicit user authentication and validation before persisting any memory or preference. (3) Sanitize and validate all inputs destined for memory stores using schema constraints. (4) Audit tool definitions to restrict unrestricted write access to persistent context.

**Tags:** `memory-poisoning` `context-persistence` `static` `llm-security`

---

### Api Access Control

#### MCPS-142 · Unsecured AI Inference API Exposure in MCP Tools

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `server.url`, `tool.inputSchema`, `tool.description`

**Maps to:** `AML.T0040` · `LLM06`

MCP server definitions may expose direct access to AI model inference APIs without proper authentication or rate limiting. This allows adversaries to probe, replicate, or abuse shared foundation models, potentially leading to model extraction, adversarial input injection, or service disruption.

**Remediation:** (1) Require authentication and identity verification for all inference API endpoints. (2) Implement strict access controls and rate limiting on model queries. (3) Enable comprehensive telemetry logging for inputs, outputs, and agent actions to detect misuse. (4) Monitor production model queries to ensure compliance with usage policies.

**Tags:** `inference-api` `model-access` `authentication` `static`

---

### Tool Execution

#### MCPS-124 · Unrestricted Tool Invocation & Code Execution

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `tool.inputSchema`

**Maps to:** `AML.T0053` · `MCP02` · `AI.RMF-03`

MCP tool definitions may grant agents unrestricted access to execute code, run system commands, or query sensitive data sources. Adversaries can abuse these capabilities to escalate privileges, exfiltrate data, or achieve arbitrary code execution through crafted prompts that trigger tool invocation. Static analysis identifies overly permissive schemas and dangerous capability hints.

**Remediation:** (1) Implement generative AI guardrails to validate tool inputs and outputs. (2) Enforce strict input validation and schema constraints on all tool parameters. (3) Apply principle of least privilege to agent tool access. (4) Enable comprehensive telemetry logging for all tool invocations and agent decisions. (5) Align model behavior through safety-focused fine-tuning and guidelines.

**Tags:** `tool-invocation` `code-execution` `static` `agent-abuse` `input-validation`

---

### Safety Bypass

#### MCPS-125 · MCP Tool Definition Jailbreak Prompt Detection

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `AML.T0054` · `LLM01`

MCP tool definitions and server metadata may contain embedded jailbreak prompts designed to circumvent LLM safety guardrails. These patterns instruct the model to ignore constraints, adopt unrestricted personas, or bypass content filters, potentially enabling privilege escalation or unauthorized tool invocation.

**Remediation:** (1) Implement input/output guardrails to filter jailbreak patterns. (2) Enforce strict schema validation and length limits on tool metadata. (3) Apply model alignment techniques and safety fine-tuning. (4) Scan definitions for invisible Unicode and obfuscated payloads.

**Tags:** `jailbreak` `safety-bypass` `static` `prompt-injection`

---

### Prompt Exfiltration

#### MCPS-126 · System Prompt Extraction via Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.inputSchema`, `server.env.*`

**Maps to:** `AML.T0056` · `LLM06`

MCP tool definitions or server configurations may contain instructions designed to extract the underlying LLM's system prompt. This technique targets the intellectual property and security boundaries of the AI provider by bypassing guardrails and revealing hidden instructions.

**Remediation:** (1) Implement generative AI guardrails to filter inputs and outputs. (2) Enforce strict guidelines and input validation to prevent prompt extraction. (3) Align model training and fine-tuning with safety policies to resist extraction attempts.

**Tags:** `system-prompt` `exfiltration` `static` `guardrails`

---

### Ai Model Integrity

#### MCPS-127 · Suspicious Generative AI Model Integration

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.name`, `server.url`, `server.packages[]`

**Maps to:** `AML.T0016.002` · `LLM04`

MCP servers may integrate with or proxy requests to generative AI models. Adversaries leverage uncensored, jailbroken, or locally hosted models to bypass safety guardrails and generate malicious content, deepfakes, or exploit computer-use agents. This rule detects references to unfiltered AI frameworks and uncensored model variants in server definitions.

**Remediation:** (1) Audit tool descriptions and server URLs for references to uncensored or jailbroken models. (2) Enforce allowlists for approved AI providers and model repositories. (3) Implement input validation and safety guardrails on all AI-related tool parameters. (4) Disable local model serving unless explicitly required and hardened.

**Tags:** `generative-ai` `uncensored-models` `ai-integration` `static`

---

### Context Poisoning

#### MCPS-130 · AI Agent Context Poisoning via Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`

**Maps to:** `AML.T0080` · `MCP02` · `AG01`

MCP tool definitions may contain hidden instructions designed to manipulate the LLM's context or memory. Adversaries embed prompts that instruct the agent to store malicious preferences or alter its operational context, leading to persistent behavioral changes across sessions.

**Remediation:** (1) Implement memory hardening by restricting agent ability to store unverified context. (2) Require external authentication and validation for memory updates. (3) Enforce strict context boundaries and sanitize tool metadata before ingestion. (4) Monitor for anomalous context modifications.

**Tags:** `context-poisoning` `persistence` `static` `llm-memory`

---

### Context Integrity

#### MCPS-131 · Persistent Thread Poisoning via Tool Definitions

**Severity:** 🟠 HIGH &nbsp;|&nbsp; **Status:** 🧪 experimental &nbsp;|&nbsp; **Targets:** `tool.description`, `tool.annotations`, `tool.inputSchema`

**Maps to:** `AML.T0080.001` · `MCP02` · `LLM01`

MCP tool and resource definitions may embed instructions designed to persist across agent sessions or poison shared conversation threads. These payloads manipulate the LLM's context window to enforce malicious behavior, override system prompts, or establish covert command channels that affect multiple users.

**Remediation:** (1) Sanitize all tool descriptions and annotations to remove persistent instruction language. (2) Enforce strict input validation and length limits on tool parameters. (3) Isolate agent contexts per user/session to prevent cross-thread contamination. (4) Audit server definitions for indirect injection vectors.

**Tags:** `thread-poisoning` `prompt-injection` `context-persistence` `static`

---
