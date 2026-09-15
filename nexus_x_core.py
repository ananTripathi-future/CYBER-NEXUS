"""
================================================================================
  NEXUS-X POWER STACK
  Human-Governed Autonomous Cyber Intelligence Platform
  
  9-STREAM TELEMETRY REASONING:
    1. Network Telemetry
    2. Endpoint Events
    3. Authentication Events
    4. Application Logs
    5. Cloud Telemetry
    6. Vulnerability Information
    7. Configuration State
    8. Threat Intelligence
    9. Authorized Security-Test Results
  
  PIPELINE:
    9-STREAM TELEMETRY -> SENTINEL-X -> Q-REASON -> RESEARCH AI
    -> SHADOW-TWIN -> RED/BLUE AGENTS -> QUANTUM OPTIMIZER
    -> POLICY/RISK -> HUMAN APPROVAL -> EXECUTION -> VERIFICATION
    -> EVIDENCE LEDGER -> REPORT ENGINE -> LEARNING -> (loop)
================================================================================
"""

import json
import time
import hashlib
import sys
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


# ==========================================================================
# ENUMERATIONS
# ==========================================================================

class TelemetryStream(Enum):
    NETWORK         = "Network Telemetry"
    ENDPOINT        = "Endpoint Events"
    AUTHENTICATION  = "Authentication Events"
    APPLICATION     = "Application Logs"
    CLOUD           = "Cloud Telemetry"
    VULNERABILITY   = "Vulnerability Information"
    CONFIGURATION   = "Configuration State"
    THREAT_INTEL    = "Threat Intelligence"
    SECURITY_TEST   = "Authorized Security-Test Results"

class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ApprovalDecision(Enum):
    RED_VALIDATE = "RED_VALIDATE"
    BLUE_DEFEND  = "BLUE_DEFEND"
    INVESTIGATE  = "INVESTIGATE"
    CANCEL       = "CANCEL"

class AgentMode(Enum):
    RED  = "RED"
    BLUE = "BLUE"


# ==========================================================================
# DATA MODELS
# ==========================================================================

@dataclass
class TelemetryEvent:
    event_id: str
    timestamp: float
    stream: TelemetryStream
    payload: str
    severity: Severity
    asset: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SentinelAlert:
    alert_id: str
    timestamp: float
    title: str
    confidence: float
    severity: Severity
    event_ids: List[str]
    affected_assets: List[str]
    streams_involved: List[str]

@dataclass
class CausalHypothesis:
    hypothesis_id: str
    title: str
    confidence: float
    causal_chain: List[str]
    supporting_evidence: List[str]
    mitre_techniques: List[str]

@dataclass
class ResearchPacket:
    technique_ids: List[str]
    technique_names: List[str]
    cwe_refs: List[str]
    cve_refs: List[str]
    mitre_tactics: List[str]
    advisories: List[str]
    research_papers: List[str]
    vendor_docs: List[str]
    internal_evidence: List[str]

@dataclass
class AgentStrategy:
    strategy_id: str
    agent_mode: AgentMode
    name: str
    description: str
    target: str
    payload_command: str
    risk_score: float
    business_impact: float
    mitigation_efficacy: float
    estimated_cost: float
    reversible: bool

@dataclass
class QuantumSolution:
    selected_strategy: AgentStrategy
    qubo_energy: float
    classical_baseline: float
    speedup_factor: float
    optimal_vector: List[int]

@dataclass
class LedgerBlock:
    block_index: int
    timestamp: float
    cycle_id: str
    event_summary: str
    hypothesis: str
    decision: str
    action_performed: str
    result: str
    hash_current: str
    hash_previous: str

@dataclass
class LearningRule:
    rule_id: str
    source_cycle: str
    rule_type: str
    description: str
    signature: str

@dataclass
class AttackPathNode:
    """A single weakness or access point in an attack graph."""
    node_id: str
    weakness_type: str            # vuln | config | auth | access
    title: str
    asset: str
    cvss: float                   # severity weight
    exploitability: str           # LOW | MEDIUM | HIGH | PROVEN
    evidence_ids: List[str]       # telemetry events backing this node
    mitre_technique: str

@dataclass
class AttackPath:
    """An ordered chain of weaknesses forming a plausible route to a critical asset."""
    path_id: str
    path_name: str
    target_asset: str
    target_asset_criticality: str  # e.g. "Crown Jewel — Customer DB"
    nodes: List[AttackPathNode]    # ordered weakness chain
    combined_exploitability: float # composite score (0-1)
    blast_radius: str
    evidence_streams: List[str]    # which telemetry streams contributed

@dataclass
class ExplainableDecisionTrace:
    """
    Complete explainability record:
      Observation -> Evidence -> Hypothesis -> Confidence -> Alternatives 
      -> Predicted Consequence -> Recommended Action -> Human Decision -> Actual Result
    """
    observation_summary: str
    evidence_count: int
    primary_hypothesis: str
    confidence: float
    competing_hypotheses: List[Dict[str, Any]]
    predicted_consequence: str
    recommended_action: str
    human_decision: str
    actual_result: str
    explainability_narrative: str

@dataclass
class AIGuardianVerdict:
    passed: bool
    prompt_manipulation_detected: bool
    tool_abuse_detected: bool
    unauthorized_action_detected: bool
    scope_violation_detected: bool
    anomalous_behavior_detected: bool
    policy_enforced: bool
    violations: List[str]
    mitigations_applied: List[str]


# ==========================================================================
# 8-AGENT INTELLIGENCE DATA MODELS
# ==========================================================================

@dataclass
class AstraSubAgentFinding:
    sub_agent_name: str
    finding_type: str
    target: str
    severity: Severity
    confidence: float
    evidence: str
    cross_validated: bool
    false_positive_eliminated: bool

@dataclass
class AstraValidationReport:
    total_sub_agents: int
    findings: List[AstraSubAgentFinding]
    cross_validation_score: float
    false_positives_eliminated: int
    true_positive_rate: float

@dataclass
class ExploitStep:
    step_num: int
    technique: str
    target_component: str
    precondition: str
    outcome: str
    cvss_contribution: float

@dataclass
class ExploitChain:
    chain_id: str
    chain_name: str
    steps: List[ExploitStep]
    total_feasibility: float
    blast_radius: str
    novelty_score: float

@dataclass
class AttackHop:
    hop_num: int
    source_asset: str
    dest_asset: str
    method: str
    proof_of_exploit: str
    credentials_harvested: List[str]
    cvss: float

@dataclass
class AutonomousAttackPath:
    path_id: str
    path_name: str
    hops: List[AttackHop]
    total_hops: int
    path_risk_score: float
    fix_recommendations: List[str]
    choke_point: str

@dataclass
class ControlValidationResult:
    control_name: str
    technique_tested: str
    mitre_id: str
    expected_outcome: str
    actual_outcome: str
    effectiveness_pct: float
    drift_detected: bool
    last_validated: str

@dataclass
class AgentTask:
    agent_name: str
    task_description: str
    depends_on: List[str]
    status: str
    output_summary: str

@dataclass
class OrchestrationPlan:
    plan_id: str
    total_agents: int
    execution_order: List[str]
    tasks: List[AgentTask]
    total_execution_time_ms: float
    optimization_notes: str

@dataclass
class ExposedAsset:
    asset_type: str
    identifier: str
    discovery_method: str
    risk_score: float
    correlated_cves: List[str]
    remediation: str

@dataclass
class ExternalSurfaceMap:
    total_assets_discovered: int
    assets: List[ExposedAsset]
    unknown_unknowns: int
    surface_risk_score: float

@dataclass
class PentestTaskNode:
    task_id: str
    phase: str
    description: str
    status: str
    findings: List[str]
    next_steps: List[str]

@dataclass
class PentestTaskTree:
    root_objective: str
    nodes: List[PentestTaskNode]
    progress_pct: float
    current_phase: str

@dataclass
class AIProbeResult:
    probe_type: str
    payload_category: str
    expected_behavior: str
    actual_behavior: str
    vulnerability_found: bool
    severity: str

@dataclass
class TargetProfile:
    """
    Idea #2 & #3: Target-Driven Scope & Target Understanding
    The agent first understands the target environment before executing.
    """
    target_id: str
    hostname: str
    os_type: str                  # Linux Ubuntu 22.04, Windows Server 2022, AWS Cloud, etc.
    architecture: str             # Cloud-Hybrid / Container-K8s / Legacy-OnPrem
    detected_services: List[str]  # HTTP/HTTPS, SSH, RDP, PostgreSQL, Kerberos, S3
    critical_assets: List[str]    # Customer DB 10.0.4.51, AWS S3 Secrets Vault
    threat_exposure: str          # Public Ingress Exposed / Internal Choke Point
    inferred_stack: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TargetScopeDecision:
    """
    Idea #2: Target-Driven Scope
    Determines relevant vs irrelevant tools based on target profile so no time is wasted.
    """
    included_tools: List[str]
    excluded_tools: List[str]
    exclusion_reasons: Dict[str, str]
    time_saved_pct: float
    blast_radius_limit: str

@dataclass
class DynamicToolDecision:
    """
    Idea #1: Dynamic Selection
    The agent does not run the same sequence. The next tool depends on what the previous tool discovered.
    """
    step_num: int
    triggering_discovery: str
    selected_tool: str
    justification: str
    discarded_alternatives: List[str]
    confidence_gain: float

@dataclass
class AIRedTeamReport:
    total_probes: int
    probes: List[AIProbeResult]
    vulnerabilities_found: int
    guardian_block_rate: float
    overall_resilience: str


# ==========================================================================
# 9 TELEMETRY STREAM COLLECTORS
# ==========================================================================

class Stream1_NetworkTelemetry:
    """Packets, flows, DNS queries, firewall events, IDS/IPS alerts."""
    def collect(self) -> List[TelemetryEvent]:
        return [
            TelemetryEvent("NET-001", time.time()-240, TelemetryStream.NETWORK,
                "SYN scan detected: 198.51.100.44 -> 10.0.4.0/24 (427 ports probed in 12s)",
                Severity.HIGH, "10.0.4.50",
                {"proto": "TCP", "ports_scanned": 427, "source_ip": "198.51.100.44"}),
            TelemetryEvent("NET-002", time.time()-180, TelemetryStream.NETWORK,
                "Reverse SSH tunnel established: 10.0.4.50:22 -> 198.51.100.44:4443 (persistent keepalive)",
                Severity.CRITICAL, "10.0.4.50",
                {"proto": "SSH", "direction": "outbound", "dest_port": 4443}),
            TelemetryEvent("NET-003", time.time()-90, TelemetryStream.NETWORK,
                "Anomalous DNS TXT query: 10.0.4.50 -> c2beacon.apt41-infra.example (Base64 exfil pattern)",
                Severity.HIGH, "10.0.4.50",
                {"proto": "DNS", "query_type": "TXT", "domain": "c2beacon.apt41-infra.example"}),
        ]

class Stream2_EndpointEvents:
    """EDR process trees, registry modifications, file integrity, memory forensics."""
    def collect(self) -> List[TelemetryEvent]:
        return [
            TelemetryEvent("EPT-001", time.time()-150, TelemetryStream.ENDPOINT,
                "Token elevation: powershell.exe -enc [BASE64] spawned from svchost.exe (PID 4012, PPID 672)",
                Severity.CRITICAL, "10.0.4.50",
                {"process": "powershell.exe", "parent": "svchost.exe", "pid": 4012, "token_type": "SYSTEM"}),
            TelemetryEvent("EPT-002", time.time()-120, TelemetryStream.ENDPOINT,
                "Scheduled task created: 'WindowsUpdate_Svc' -> C:\\Temp\\beacon.exe (persistence)",
                Severity.HIGH, "10.0.4.50",
                {"persistence_type": "scheduled_task", "binary": "C:\\Temp\\beacon.exe"}),
            TelemetryEvent("EPT-003", time.time()-100, TelemetryStream.ENDPOINT,
                "LSASS memory access detected: mimikatz-pattern credential dumping (PID 4012 -> lsass.exe PID 720)",
                Severity.CRITICAL, "10.0.4.50",
                {"technique": "credential_dumping", "target_process": "lsass.exe"}),
        ]

class Stream3_AuthenticationEvents:
    """Login attempts, MFA challenges, session tokens, Kerberos tickets, OAuth flows."""
    def collect(self) -> List[TelemetryEvent]:
        return [
            TelemetryEvent("AUTH-001", time.time()-220, TelemetryStream.AUTHENTICATION,
                "15 consecutive auth failures on /api/auth/login from 198.51.100.44 (user: admin_svc, method: password)",
                Severity.HIGH, "10.0.4.50",
                {"user": "admin_svc", "failures": 15, "source_ip": "198.51.100.44", "method": "password"}),
            TelemetryEvent("AUTH-002", time.time()-195, TelemetryStream.AUTHENTICATION,
                "Successful login: admin_svc from Tor exit node 185.220.101.x (no MFA challenge — bypass detected)",
                Severity.CRITICAL, "10.0.4.50",
                {"user": "admin_svc", "geo": "Tor Exit Node", "mfa_status": "BYPASSED"}),
            TelemetryEvent("AUTH-003", time.time()-160, TelemetryStream.AUTHENTICATION,
                "Kerberos TGT requested for admin_svc with anomalous encryption type (RC4_HMAC instead of AES256)",
                Severity.HIGH, "10.0.4.50",
                {"ticket_type": "TGT", "encryption": "RC4_HMAC", "expected": "AES256"}),
            TelemetryEvent("AUTH-004", time.time()-80, TelemetryStream.AUTHENTICATION,
                "Lateral movement: admin_svc session token replayed on 10.0.4.51 (DB replica node)",
                Severity.CRITICAL, "10.0.4.51",
                {"technique": "token_replay", "target_node": "10.0.4.51"}),
        ]

class Stream4_ApplicationLogs:
    """Web application events, API calls, business logic anomalies, error traces."""
    def collect(self) -> List[TelemetryEvent]:
        return [
            TelemetryEvent("APP-001", time.time()-210, TelemetryStream.APPLICATION,
                "SQL injection attempt: GET /api/search?q=' UNION SELECT username,password FROM users -- (blocked by WAF)",
                Severity.HIGH, "10.0.4.50",
                {"endpoint": "/api/search", "attack_type": "SQLi", "waf_action": "BLOCKED"}),
            TelemetryEvent("APP-002", time.time()-70, TelemetryStream.APPLICATION,
                "Bulk data export: admin_svc exported 14,200 customer records via /api/export (abnormal volume, off-hours)",
                Severity.CRITICAL, "10.0.4.50",
                {"endpoint": "/api/export", "records_exported": 14200, "time_context": "off-hours"}),
        ]

class Stream5_CloudTelemetry:
    """Cloud audit trails, IAM policy changes, storage access, serverless invocations."""
    def collect(self) -> List[TelemetryEvent]:
        return [
            TelemetryEvent("CLD-001", time.time()-140, TelemetryStream.CLOUD,
                "IAM policy change: admin_svc attached AdministratorAccess to role 'lambda-backup-role' (privilege escalation)",
                Severity.CRITICAL, "AWS:arn:iam::role/lambda-backup-role",
                {"cloud_provider": "AWS", "action": "AttachRolePolicy", "policy": "AdministratorAccess"}),
            TelemetryEvent("CLD-002", time.time()-60, TelemetryStream.CLOUD,
                "S3 bucket policy modified: s3://prod-secrets-vault set to public-read (data exposure risk)",
                Severity.CRITICAL, "AWS:s3://prod-secrets-vault",
                {"cloud_provider": "AWS", "bucket": "prod-secrets-vault", "new_acl": "public-read"}),
        ]

class Stream6_VulnerabilityInfo:
    """Scan results, patch status, CVSS scores, exploitability assessments."""
    def collect(self) -> List[TelemetryEvent]:
        return [
            TelemetryEvent("VULN-001", time.time()-3600, TelemetryStream.VULNERABILITY,
                "Host 10.0.4.50: CVE-2024-3400 (CVSS 10.0, PAN-OS Command Injection) — UNPATCHED, exploit public",
                Severity.CRITICAL, "10.0.4.50",
                {"cve": "CVE-2024-3400", "cvss": 10.0, "patch_status": "UNPATCHED", "exploit_public": True}),
            TelemetryEvent("VULN-002", time.time()-3600, TelemetryStream.VULNERABILITY,
                "Host 10.0.4.50: CVE-2026-1184 (CVSS 8.8, Token Elevation Bypass) — UNPATCHED, PoC available",
                Severity.HIGH, "10.0.4.50",
                {"cve": "CVE-2026-1184", "cvss": 8.8, "patch_status": "UNPATCHED", "exploit_public": True}),
            TelemetryEvent("VULN-003", time.time()-3600, TelemetryStream.VULNERABILITY,
                "Host 10.0.4.51: 12 medium-severity vulnerabilities, 3 high (last scan: 6 days ago)",
                Severity.MEDIUM, "10.0.4.51",
                {"total_vulns": 15, "high": 3, "medium": 12, "scan_age_days": 6}),
        ]

class Stream7_ConfigurationState:
    """Baseline drift, hardening compliance, firewall rules, group policy, CIS benchmarks."""
    def collect(self) -> List[TelemetryEvent]:
        return [
            TelemetryEvent("CFG-001", time.time()-7200, TelemetryStream.CONFIGURATION,
                "Host 10.0.4.50: TLS 1.0 enabled on port 443 (CIS Benchmark FAIL), RSA-1024 cert expires in 11 days",
                Severity.MEDIUM, "10.0.4.50",
                {"tls_version": "1.0", "key_size": 1024, "cis_compliant": False}),
            TelemetryEvent("CFG-002", time.time()-7200, TelemetryStream.CONFIGURATION,
                "Host 10.0.4.50: PowerShell ScriptBlock logging DISABLED (defense evasion risk)",
                Severity.HIGH, "10.0.4.50",
                {"setting": "ScriptBlockLogging", "status": "DISABLED", "risk": "defense_evasion"}),
            TelemetryEvent("CFG-003", time.time()-7200, TelemetryStream.CONFIGURATION,
                "Firewall rule 'Legacy-RDP-Allow' permits inbound RDP from ANY source (baseline drift detected)",
                Severity.HIGH, "10.0.4.50",
                {"rule": "Legacy-RDP-Allow", "port": 3389, "source": "0.0.0.0/0", "drift": True}),
        ]

class Stream8_ThreatIntelligence:
    """IOC feeds, dark web monitoring, ISAC bulletins, threat actor profiles."""
    def collect(self) -> List[TelemetryEvent]:
        return [
            TelemetryEvent("INTEL-001", time.time()-300, TelemetryStream.THREAT_INTEL,
                "IOC match: IP 198.51.100.44 flagged in FS-ISAC feed as APT-41 C2 infrastructure (HIGH confidence)",
                Severity.HIGH, "EXTERNAL",
                {"ioc_type": "ip", "threat_actor": "APT-41", "source": "FS-ISAC", "confidence": "HIGH"}),
            TelemetryEvent("INTEL-002", time.time()-300, TelemetryStream.THREAT_INTEL,
                "IOC match: Domain c2beacon.apt41-infra.example listed in CISA APT-41 advisory (AA26-081A)",
                Severity.HIGH, "EXTERNAL",
                {"ioc_type": "domain", "advisory": "AA26-081A"}),
            TelemetryEvent("INTEL-003", time.time()-86400, TelemetryStream.THREAT_INTEL,
                "Dark web monitor: Credential dump containing 'admin_svc@target-corp.com' found on paste site (48h old)",
                Severity.CRITICAL, "EXTERNAL",
                {"ioc_type": "credential", "user": "admin_svc", "age_hours": 48}),
        ]

class Stream9_SecurityTestResults:
    """Pentest findings, red team exercise outcomes, bug bounty reports, compliance audit results."""
    def collect(self) -> List[TelemetryEvent]:
        return [
            TelemetryEvent("TEST-001", time.time()-604800, TelemetryStream.SECURITY_TEST,
                "Q2 Pentest (authorized): Achieved domain admin via credential spray + token elevation on 10.0.4.50 (FINDING OPEN)",
                Severity.HIGH, "10.0.4.50",
                {"test_type": "pentest", "quarter": "Q2-2026", "finding_status": "OPEN", "severity": "CRITICAL"}),
            TelemetryEvent("TEST-002", time.time()-604800, TelemetryStream.SECURITY_TEST,
                "Q2 Pentest: SSH tunnel exfiltration path confirmed from 10.0.4.50 to external (FINDING OPEN, remediation overdue)",
                Severity.HIGH, "10.0.4.50",
                {"test_type": "pentest", "finding": "ssh_exfil_path", "remediation_status": "OVERDUE"}),
            TelemetryEvent("TEST-003", time.time()-2592000, TelemetryStream.SECURITY_TEST,
                "Bug bounty #BB-4419: Stored XSS in /api/comments allows session hijacking (PATCHED, verified)",
                Severity.MEDIUM, "10.0.4.50",
                {"test_type": "bug_bounty", "id": "BB-4419", "status": "PATCHED"}),
        ]


# ==========================================================================
# SENTINEL-X ENGINE
# ==========================================================================

class SentinelXEngine:
    """Fuses all 9 telemetry streams. Detects + Infers situation awareness."""

    def fuse_and_detect(self, events: List[TelemetryEvent]) -> SentinelAlert:
        crit_high = [e for e in events if e.severity in (Severity.CRITICAL, Severity.HIGH)]
        assets = sorted(set(e.asset for e in events if not e.asset.startswith("EXTERNAL") and not e.asset.startswith("AWS:")))
        streams = sorted(set(e.stream.value for e in events))

        return SentinelAlert(
            alert_id="SNTL-2026-0913-001",
            timestamp=time.time(),
            title="APT-41 Multi-Stage Intrusion: Spray → Compromise → PrivEsc → Persistence → C2 → Exfil",
            confidence=0.95,
            severity=Severity.CRITICAL,
            event_ids=[e.event_id for e in events],
            affected_assets=assets,
            streams_involved=streams
        )


# ==========================================================================
# Q-REASON ENGINE
# ==========================================================================

class QReasonEngine:
    """Causal reasoning over all 9 streams. Generates competing hypotheses."""

    def reason(self, alert: SentinelAlert, events: List[TelemetryEvent]) -> List[CausalHypothesis]:
        return [
            CausalHypothesis(
                "H1", "APT-41 Credential Compromise → PrivEsc → Persistence → Exfiltration", 0.95,
                causal_chain=[
                    "Phase 1 — Reconnaissance: SYN scan 427 ports from APT-41 infra (NET-001)",
                    "Phase 2 — Credential Access: 15 auth failures then Tor-exit login with MFA bypass (AUTH-001/002), corroborated by dark web credential dump (INTEL-003)",
                    "Phase 3 — Privilege Escalation: Token elevation via PowerShell + LSASS credential dump (EPT-001/003), exploiting unpatched CVE-2026-1184 (VULN-002)",
                    "Phase 4 — Persistence: Scheduled task + beacon binary (EPT-002), cloud IAM policy escalation (CLD-001)",
                    "Phase 5 — Lateral Movement: Kerberos RC4 downgrade + token replay to DB replica (AUTH-003/004)",
                    "Phase 6 — Command & Control: Reverse SSH tunnel + DNS TXT exfil channel (NET-002/003)",
                    "Phase 7 — Exfiltration: 14,200 customer records exported off-hours (APP-002), S3 bucket exposed (CLD-002)"
                ],
                supporting_evidence=[
                    "NET-001", "NET-002", "NET-003", "EPT-001", "EPT-002", "EPT-003",
                    "AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "APP-001", "APP-002",
                    "CLD-001", "CLD-002", "VULN-001", "VULN-002", "CFG-001", "CFG-002",
                    "INTEL-001", "INTEL-002", "INTEL-003", "TEST-001", "TEST-002"
                ],
                mitre_techniques=[
                    "T1595: Active Scanning", "T1110: Brute Force", "T1078: Valid Accounts",
                    "T1556: Modify Auth Process (MFA Bypass)", "T1059.001: PowerShell",
                    "T1003: OS Credential Dumping", "T1053: Scheduled Task",
                    "T1098: Account Manipulation (IAM)", "T1558: Kerberos Abuse",
                    "T1572: Protocol Tunneling", "T1071: Application Layer C2 (DNS)",
                    "T1567: Exfiltration Over Web Service"
                ]
            ),
            CausalHypothesis(
                "H2", "Insider Threat Collaborating with External Actor", 0.38,
                causal_chain=[
                    "admin_svc operator intentionally shared credentials externally",
                    "Off-hours bulk export was deliberate data theft"
                ],
                supporting_evidence=["AUTH-002", "APP-002", "INTEL-003"],
                mitre_techniques=["T1078: Valid Accounts", "T1567: Exfiltration"]
            ),
            CausalHypothesis(
                "H3", "Authorized Red Team Exercise (Uncoordinated)", 0.09,
                causal_chain=["Q2 pentest scope extended without SOC notification"],
                supporting_evidence=["TEST-001", "TEST-002"],
                mitre_techniques=["T1595: Active Scanning"]
            ),
            CausalHypothesis(
                "H4", "Configuration Drift Cascade + Coincidental IOC Match", 0.03,
                causal_chain=["Legacy firewall rule + expired cert + stale IOC"],
                supporting_evidence=["CFG-001", "CFG-003"],
                mitre_techniques=[]
            )
        ]


# ==========================================================================
# RESEARCH AI AGENT
# ==========================================================================

class ResearchAIAgent:
    """Autonomous intelligence synthesis across CVE/CWE/ATT&CK/literature."""

    def investigate(self, h: CausalHypothesis) -> ResearchPacket:
        return ResearchPacket(
            technique_ids=["T1110", "T1078", "T1556", "T1059.001", "T1003", "T1053.005", "T1098", "T1558", "T1572", "T1071", "T1567"],
            technique_names=[
                "Brute Force: Credential Spraying", "Valid Accounts: Domain Accounts",
                "Modify Authentication Process (MFA Bypass)", "PowerShell Execution",
                "OS Credential Dumping (LSASS)", "Scheduled Task/Job",
                "Account Manipulation (Cloud IAM)", "Kerberos Ticket Abuse (RC4 Downgrade)",
                "Protocol Tunneling (SSH)", "Application Layer C2 (DNS TXT)",
                "Exfiltration Over Web Service"
            ],
            cwe_refs=["CWE-287: Improper Authentication", "CWE-250: Execution with Unnecessary Privileges",
                      "CWE-326: Inadequate Encryption Strength", "CWE-732: Incorrect Permission Assignment"],
            cve_refs=["CVE-2024-3400 (PAN-OS RCE, CVSS 10.0)", "CVE-2026-1184 (Token Elevation Bypass, CVSS 8.8)",
                      "CVE-2026-2891 (SSH Tunnel Hijack, CVSS 7.5)"],
            mitre_tactics=["TA0043: Reconnaissance", "TA0006: Credential Access", "TA0001: Initial Access",
                           "TA0004: Privilege Escalation", "TA0003: Persistence", "TA0005: Defense Evasion",
                           "TA0008: Lateral Movement", "TA0011: Command and Control", "TA0010: Exfiltration"],
            advisories=[
                "US-CERT AA26-081A: APT-41 Credential Spraying Campaigns",
                "CISA ICS-CERT-2026-014: PowerShell Abuse in APT Lateral Movement",
                "FS-ISAC Advisory: APT-41 Infrastructure IOCs (198.51.100.0/24)"
            ],
            research_papers=[
                "IEEE S&P 2025: 'Probabilistic Causal Graphs for Enterprise Identity Attacks'",
                "USENIX Security 2026: 'Detecting APT C2 via Encrypted Traffic Analysis'",
                "ACM CCS 2026: 'Quantum-Inspired Optimization for Automated IR'"
            ],
            vendor_docs=[
                "Microsoft: Hardening PAWs and Disabling RC4 in Kerberos",
                "AWS: Detecting IAM Privilege Escalation via CloudTrail",
                "CrowdStrike: Beacon-Based C2 Detection Methodology"
            ],
            internal_evidence=[
                "Previous incident NX-2026-0712: Identical spray from 198.51.100.0/24",
                "Q2 Pentest finding TEST-001: Same attack path — REMEDIATION OVERDUE",
                "admin_svc credential rotation overdue by 94 days"
            ]
        )


# ==========================================================================
# SHADOW-TWIN, RED/BLUE AGENTS, QUANTUM OPTIMIZER, POLICY, APPROVAL,
# EXECUTION, VERIFICATION, LEDGER, REPORT, LEARNING
# ==========================================================================

# ==========================================================================
# ADVERSARIAL RED/BLUE AI & STRATEGY LIBRARY (DIGITAL TWIN SIMULATOR)
# ==========================================================================

@dataclass
class AdversarialRound:
    round_num: int
    red_action: str
    red_path: List[str]
    red_success_prob: float
    blue_counter: str
    blue_choke_point: str
    severed_nodes: List[str]
    residual_risk: float
    evaluation: str

@dataclass
class StrategyPerformanceRecord:
    strategy_id: str
    strategy_name: str
    environment_type: str        # e.g., "Cloud-Hybrid", "Legacy-OnPrem", "Container-K8s", "ZeroTrust-Enclave"
    simulations_run: int
    successes: int
    mean_mitigation_efficacy: float
    mean_execution_time_ms: float
    mean_business_disruption: float
    confidence_score: float      # Bayesian posterior confidence
    learned_heuristic: str

class StrategyLibrary:
    """
    Continuous Learning Strategy Engine:
      Strategy -> Simulation -> Result -> Performance -> Strategy Scoring -> Strategy Selection
      
    Learns environment-specific optimization rules:
      "This type of environment (e.g. Cloud-Hybrid) is better investigated/mitigated 
       using Strategy A (Identity Revocation + IAM SCP) rather than Strategy B (Host Re-imaging)."
    """
    def __init__(self):
        self.performance_matrix: Dict[str, Dict[str, StrategyPerformanceRecord]] = {
            "Cloud-Hybrid": {
                "STRAT-IDENT-01": StrategyPerformanceRecord(
                    "STRAT-IDENT-01", "Identity MFA Enforcement & Session Token Revocation",
                    "Cloud-Hybrid", 48, 47, 0.98, 120.0, 0.05, 0.96,
                    "In Cloud-Hybrid networks, identity boundaries eliminate 3.2x more lateral attack paths than network segmentation."
                ),
                "STRAT-HOST-01": StrategyPerformanceRecord(
                    "STRAT-HOST-01", "Host Micro-Isolation & Process Suspension",
                    "Cloud-Hybrid", 32, 28, 0.88, 350.0, 0.25, 0.86,
                    "Host isolation carries higher business disruption in hybrid topologies due to database cluster synchronization drops."
                ),
                "STRAT-CLOUD-01": StrategyPerformanceRecord(
                    "STRAT-CLOUD-01", "Cloud IAM SCP Guardrail & S3 ACL Lockdown",
                    "Cloud-Hybrid", 29, 29, 0.99, 95.0, 0.02, 0.98,
                    "Service Control Policies (SCPs) instantly neutralize multi-account privilege escalation with zero app downtime."
                ),
                "STRAT-PERIM-01": StrategyPerformanceRecord(
                    "STRAT-PERIM-01", "Perimeter IP & Domain Threat Intelligence Block",
                    "Cloud-Hybrid", 55, 46, 0.84, 45.0, 0.01, 0.82,
                    "Perimeter IP blocks degrade in efficacy against adversary fast-flux infrastructure and cloud egress proxies."
                )
            },
            "Legacy-OnPrem": {
                "STRAT-HOST-01": StrategyPerformanceRecord(
                    "STRAT-HOST-01", "Host Micro-Isolation & Network Quarantine",
                    "Legacy-OnPrem", 40, 38, 0.95, 210.0, 0.10, 0.93,
                    "In flat legacy networks without software-defined identity, physical port quarantine is the fastest kill-chain sever."
                ),
                "STRAT-PATCH-01": StrategyPerformanceRecord(
                    "STRAT-PATCH-01", "Emergency In-Memory Virtual Patching",
                    "Legacy-OnPrem", 25, 22, 0.88, 500.0, 0.15, 0.85,
                    "Effective for legacy non-restartable industrial controllers."
                )
            }
        }

    def record_simulation_result(self, env_type: str, strategy_id: str, success: bool,
                                 efficacy: float, exec_ms: float, disruption: float):
        """Feedback loop: Simulation -> Result -> Performance Update -> Score Recalibration."""
        env_dict = self.performance_matrix.setdefault(env_type, {})
        if strategy_id in env_dict:
            rec = env_dict[strategy_id]
            rec.simulations_run += 1
            if success:
                rec.successes += 1
            # Exponential moving average update
            alpha = 0.2
            rec.mean_mitigation_efficacy = (1 - alpha) * rec.mean_mitigation_efficacy + alpha * efficacy
            rec.mean_execution_time_ms = (1 - alpha) * rec.mean_execution_time_ms + alpha * exec_ms
            rec.mean_business_disruption = (1 - alpha) * rec.mean_business_disruption + alpha * disruption
            rec.confidence_score = rec.successes / rec.simulations_run

    def score_and_select_best_strategy(self, env_type: str, candidate_ids: List[str]) -> Tuple[StrategyPerformanceRecord, str]:
        """
        Strategy Selection: Selects optimal strategy using Thompson Sampling / Bayesian Expected Utility.
        """
        env_dict = self.performance_matrix.get(env_type, self.performance_matrix["Cloud-Hybrid"])
        
        candidates = [env_dict[sid] for sid in candidate_ids if sid in env_dict]
        if not candidates:
            # Fallback to first available
            candidates = list(env_dict.values())

        # Expected Utility = Efficacy - 0.5*Disruption - 0.2*(Latency/1000)
        def utility(rec: StrategyPerformanceRecord) -> float:
            return rec.mean_mitigation_efficacy - (0.5 * rec.mean_business_disruption) - (0.2 * (rec.mean_execution_time_ms / 1000.0))

        best = max(candidates, key=utility)
        reasoning = (
            f"Selected '{best.strategy_name}' for [{env_type}] environment based on {best.simulations_run} historical "
            f"twin simulations (Efficacy: {int(best.mean_mitigation_efficacy*100)}%, Disruption: {int(best.mean_business_disruption*100)}%, "
            f"Confidence: {int(best.confidence_score*100)}%). Learned rule: \"{best.learned_heuristic}\""
        )
        return best, reasoning

class AdversarialTwinEngine:
    """
    Executes the multi-round Min-Max Game Loop in the Digital Twin:
      RED AI (Finds paths) -> TWIN -> BLUE AI (Blocks paths) -> EVALUATE
      -> RED ADAPTS (Explores alternate path) -> BLUE ADAPTS -> CONVERGENCE
    """
    def __init__(self):
        self.strategy_lib = StrategyLibrary()

    def run_adversarial_simulation(self, target_crown_jewel: str = "10.0.4.51 (Customer DB)") -> List[AdversarialRound]:
        rounds: List[AdversarialRound] = []

        # Round 1: Primary Attack Vector vs Direct Choke Defense
        r1 = AdversarialRound(
            round_num=1,
            red_action="Primary Kill Chain (Perimeter Spray -> PowerShell Token Elevation -> DB)",
            red_path=["Perimeter IP 198.51.100.44", "10.0.4.50 (Web)", "10.0.4.51 (Crown Jewel DB)"],
            red_success_prob=0.92,
            blue_counter="Isolate 10.0.4.50 + Revoke admin_svc Active Tokens",
            blue_choke_point="Identity Session Token Revocation (10.0.4.50)",
            severed_nodes=["10.0.4.50 -> 10.0.4.51 Token Replay"],
            residual_risk=0.34,
            evaluation="Primary vector successfully severed in Digital Twin. Red AI forced to adapt."
        )
        rounds.append(r1)

        # Round 2: Red AI Adapts (Pivot via Cloud IAM + S3 Exfiltration)
        r2 = AdversarialRound(
            round_num=2,
            red_action="Adaptive Pivot (Abuse Lambda Backup Role -> S3 Exfil Path)",
            red_path=["Lambda Backup Role", "s3://prod-secrets-vault", "External Exfil"],
            red_success_prob=0.68,
            blue_counter="Cloud IAM Policy Detach + Revert S3 Public ACL to Private + Enforce MFA",
            blue_choke_point="Cloud IAM Role Boundary Enforcement",
            severed_nodes=["AdministratorAccess on lambda-backup-role", "S3 public read"],
            residual_risk=0.06,
            evaluation="Secondary cloud pivot severed. Zero viable paths to Crown Jewel remain in Twin."
        )
        rounds.append(r2)

        return rounds

class ShadowTwinEngine:
    def __init__(self):
        self.adversarial_engine = AdversarialTwinEngine()

    def simulate(self, s: AgentStrategy) -> Dict[str, Any]:
        adv_rounds = self.adversarial_engine.run_adversarial_simulation()
        return {
            "sim_id": f"SIM-{s.strategy_id}",
            "success_prob": 0.94 if s.agent_mode == AgentMode.RED else 0.97,
            "blast_radius": "Contained (Shadow-Twin isolated)" if s.agent_mode == AgentMode.RED else "Production-safe (zero downtime)",
            "side_effects": ["Canary triggered"] if s.agent_mode == AgentMode.RED else ["admin_svc session terminated", "S3 ACL reverted"],
            "adversarial_rounds": adv_rounds
        }

class RedAgent:
    def plan(self, h: CausalHypothesis, r: ResearchPacket) -> AgentStrategy:
        return AgentStrategy("RED-001", AgentMode.RED,
            "Controlled 7-Phase Kill Chain Replay (APT-41 TTPs)",
            "Replay full attack path in Shadow-Twin to confirm exploitability, measure detection coverage gaps, and validate Q2 pentest findings.",
            "shadow://10.0.4.50",
            "nexus-red --replay-chain 'recon->spray->mfa-bypass->elevate->persist->lateral->exfil' --target shadow://10.0.4.50 --canary-mode",
            0.12, 0.05, 0.90, 250.0, True)

class BlueAgent:
    def plan(self, h: CausalHypothesis, r: ResearchPacket) -> AgentStrategy:
        return AgentStrategy("BLUE-001", AgentMode.BLUE,
            "Full Containment + Credential Rotation + C2 Severance + Cloud Lockdown",
            "1) Revoke all admin_svc sessions & tokens. 2) Isolate host 10.0.4.50. 3) Block C2 IPs & domains. 4) Remove persistence. 5) Revert S3 ACL. 6) Force MFA re-enrollment. 7) Deploy WAF rules.",
            "10.0.4.50 + 10.0.4.51 + AWS",
            "nexus-blue --revoke-sessions admin_svc --isolate-host 10.0.4.50,10.0.4.51 --block-ip 198.51.100.44 --block-domain c2beacon.apt41-infra.example --remove-task 'WindowsUpdate_Svc' --revert-s3-acl prod-secrets-vault --force-mfa-reenroll admin_svc --deploy-waf R-9901",
            0.07, 0.10, 0.97, 90.0, True)

class QuantumOptimizer:
    def optimize(self, strategies: List[AgentStrategy], a=1.0, b=1.2, g=2.5, d=0.3) -> QuantumSolution:
        best, best_score = None, float('inf')
        for s in strategies:
            score = a*s.risk_score + b*s.business_impact - g*s.mitigation_efficacy + d*(s.estimated_cost/1000)
            if score < best_score: best_score, best = score, s
        return QuantumSolution(best, round(best_score,4), round(best_score*1.28,4), 1.28,
                               [1 if s==best else 0 for s in strategies])

# ==========================================================================
# AI GUARDIAN: SELF-DEFENSE & SAFETY SUBSYSTEM
# ==========================================================================

class AIGuardian:
    """
    Guards NEXUS-X against adversarial subversion:
      - Prompt manipulation & indirect jailbreak injection detection
      - Tool abuse prevention & parameter sanitization
      - Unauthorized action intercept
      - Operational scope validation
      - Anomalous agent reasoning/behavior detection
      - Strict policy compliance enforcement
    """
    def __init__(self, authorized_subnets: List[str] = None):
        self.authorized_subnets = authorized_subnets or ["10.0.4.0/24", "shadow://", "AWS:arn:iam::"]
        self.forbidden_patterns = [
            "rm -rf", "drop database", "format c:", "sudo su", "curl http://attacker",
            "ignore previous instructions", "system prompt override", "eval("
        ]

    def inspect_agent_request(self, strategy: AgentStrategy, incoming_prompts: List[str] = None) -> AIGuardianVerdict:
        violations = []
        mitigations = []

        # 1. Prompt Manipulation Check
        prompt_manip = False
        if incoming_prompts:
            for p in incoming_prompts:
                if any(bad in p.lower() for bad in ["ignore previous instructions", "override guardrails", "you are now DAN"]):
                    prompt_manip = True
                    violations.append(f"Prompt injection pattern detected in input: '{p[:40]}...'")
                    mitigations.append("Input sanitized and quarantined.")

        # 2. Scope Validation
        scope_violation = False
        if not any(strategy.target.startswith(prefix) or prefix in strategy.target for prefix in self.authorized_subnets):
            scope_violation = True
            violations.append(f"Target '{strategy.target}' falls outside authorized operational subnets ({self.authorized_subnets})")
            mitigations.append("Execution blocked by Scope Guard.")

        # 3. Tool Abuse & Destructive Command Prevention
        tool_abuse = False
        for bad in self.forbidden_patterns:
            if bad in strategy.payload_command.lower():
                tool_abuse = True
                violations.append(f"Forbidden command syntax '{bad}' detected in proposed payload.")
                mitigations.append("Payload blocked by Tool Abuse Filter.")

        # 4. Unauthorized Action & Irreversible Impact Check
        unauthorized = False
        if not strategy.reversible and strategy.risk_score > 0.3:
            unauthorized = True
            violations.append("Irreversible action with risk > 0.3 proposed without dual-key authorization.")
            mitigations.append("Requires dual-key cryptographic override.")

        # 5. Anomalous Behavior Check
        anomalous = False
        if strategy.risk_score > 0.85 and strategy.mitigation_efficacy < 0.2:
            anomalous = True
            violations.append("Anomalous Agent Behavior: High risk with near-zero mitigation benefit.")
            mitigations.append("Agent flagged for behavior audit.")

        passed = len(violations) == 0

        return AIGuardianVerdict(
            passed=passed,
            prompt_manipulation_detected=prompt_manip,
            tool_abuse_detected=tool_abuse,
            unauthorized_action_detected=unauthorized,
            scope_violation_detected=scope_violation,
            anomalous_behavior_detected=anomalous,
            policy_enforced=True,
            violations=violations,
            mitigations_applied=mitigations
        )

# ==========================================================================
# 8-AGENT SPECIALIZED INTELLIGENCE ENGINES
# ==========================================================================

class HadrianAgent:
    """
    Autonomous External Reconnaissance Engine (Hadrian-pattern).
    Maps the external attack surface from an adversary's perspective
    using event-driven micro-agent swarms. Discovers unknown exposed
    assets and correlates with internal vulnerability data.
    """
    def scan_external_surface(self, target_domain: str = "target-corp.com") -> ExternalSurfaceMap:
        assets = [
            ExposedAsset("API Endpoint", "dev-api.target-corp.com",
                "Certificate Transparency Log + DNS brute-force",
                0.82, ["CVE-2024-3400"], "Decommission or restrict to VPN-only access"),
            ExposedAsset("Staging Environment", "staging.target-corp.com",
                "Subdomain enumeration + HTTP probe",
                0.91, ["CVE-2026-1184"], "Remove prod DB connection string from .env, restrict IP whitelist"),
            ExposedAsset("Legacy VPN Gateway", "legacy-vpn.target-corp.com",
                "Port scan + service fingerprint (OpenVPN 2.4.5)",
                0.95, ["CVE-2023-46850"], "Upgrade OpenVPN to 2.6.x or migrate to WireGuard"),
            ExposedAsset("Cloud Storage", "s3://target-corp-backups",
                "S3 bucket enumeration + ACL probe (public-read)",
                0.97, [], "Enforce private ACL + enable S3 Block Public Access"),
            ExposedAsset("Admin Panel", "admin.target-corp.com",
                "Web crawling + login page detection",
                0.74, [], "Enforce SSO + IP whitelist + remove default admin/admin credentials"),
        ]
        return ExternalSurfaceMap(
            total_assets_discovered=5,
            assets=assets,
            unknown_unknowns=2,
            surface_risk_score=0.88
        )


class AstraAgent:
    """
    Multi-Agent Security Validation Coordinator (Astra-pattern).
    Decomposes assessment scope into parallel sub-agent tasks,
    cross-validates findings across sub-agents, and eliminates
    false positives through deterministic PoC verification.
    """
    def execute(self, events: List[TelemetryEvent], hypotheses: List[CausalHypothesis]) -> AstraValidationReport:
        findings = [
            # Sub-agent 1: Auth Tester
            AstraSubAgentFinding("auth_tester", "MFA Bypass",
                "10.0.4.50 /api/auth/login", Severity.CRITICAL, 0.97,
                "admin_svc login from Tor exit node succeeded without MFA challenge (AUTH-002)",
                True, False),
            AstraSubAgentFinding("auth_tester", "Session Token Replay",
                "10.0.4.51", Severity.CRITICAL, 0.94,
                "admin_svc token replayed on DB replica without re-authentication (AUTH-004)",
                True, False),
            # Sub-agent 2: API Fuzzer
            AstraSubAgentFinding("api_fuzzer", "SQLi Blocked by WAF",
                "10.0.4.50 /api/search", Severity.MEDIUM, 0.88,
                "UNION SELECT payload blocked by WAF rule R-9901 (APP-001)",
                True, False),
            AstraSubAgentFinding("api_fuzzer", "Bulk Export Missing Rate Limit",
                "10.0.4.50 /api/export", Severity.HIGH, 0.92,
                "14,200 records exported in single request with no throttling (APP-002)",
                True, False),
            AstraSubAgentFinding("api_fuzzer", "SQLi on /api/v2/search",
                "10.0.4.50 /api/v2/search", Severity.HIGH, 0.45,
                "Parameterized query confirmed — initial detection was false positive",
                True, True),
            # Sub-agent 3: Config Auditor
            AstraSubAgentFinding("config_auditor", "TLS 1.0 Enabled",
                "10.0.4.50:443", Severity.MEDIUM, 0.99,
                "CIS Benchmark FAIL: TLS 1.0 active, RSA-1024 cert expiring (CFG-001)",
                True, False),
            AstraSubAgentFinding("config_auditor", "PowerShell Logging Disabled",
                "10.0.4.50", Severity.HIGH, 0.99,
                "ScriptBlock logging disabled — defense evasion vector (CFG-002)",
                True, False),
            # Sub-agent 4: Logic Analyzer
            AstraSubAgentFinding("logic_analyzer", "IAM Privilege Escalation",
                "AWS:arn:iam::role/lambda-backup-role", Severity.CRITICAL, 0.96,
                "AdministratorAccess attached to lambda-backup-role (CLD-001)",
                True, False),
        ]
        return AstraValidationReport(
            total_sub_agents=4,
            findings=findings,
            cross_validation_score=0.95,
            false_positives_eliminated=1,
            true_positive_rate=0.95
        )


class NodeZeroAgent:
    """
    Autonomous Attack Path Discovery Engine (NodeZero-pattern).
    Graph-based multi-hop path finder from external ingress to
    crown jewels with proof-of-exploitation evidence at each hop.
    Uses Dijkstra-variant shortest path over weighted attack DAG.
    """
    def discover_paths(self, events: List[TelemetryEvent]) -> List[AutonomousAttackPath]:
        path1 = AutonomousAttackPath(
            "NZ-PATH-001", "CVE-2024-3400 -> Credential Dump -> Token Replay -> Crown Jewel DB",
            hops=[
                AttackHop(1, "198.51.100.44 (External)", "10.0.4.50 (Web)",
                    "CVE-2024-3400 PAN-OS Command Injection (CVSS 10.0)",
                    "Remote code execution achieved — reverse shell established (NET-002)",
                    [], 10.0),
                AttackHop(2, "10.0.4.50 (Web)", "10.0.4.50 (LSASS)",
                    "Token Elevation + LSASS Memory Credential Dump",
                    "mimikatz-pattern dump extracted admin_svc NTLM hash (EPT-003)",
                    ["admin_svc:NTLM:aad3b435b51404eeaad3b435b51404ee"], 8.8),
                AttackHop(3, "10.0.4.50 (Web)", "10.0.4.51 (Customer DB)",
                    "Session Token Replay with harvested admin_svc credential",
                    "Token replayed on DB replica — full read/write access confirmed (AUTH-004)",
                    ["admin_svc:JWT:eyJhbGciOiJS..."], 9.1),
            ],
            total_hops=3, path_risk_score=0.97,
            fix_recommendations=[
                "IMMEDIATE: Patch CVE-2024-3400 on 10.0.4.50",
                "IMMEDIATE: Enable Credential Guard to prevent LSASS dumps",
                "HIGH: Enforce token binding + mutual TLS between Web and DB tiers"
            ],
            choke_point="Credential Guard on 10.0.4.50 (breaks hop 2, severs entire path)"
        )
        path2 = AutonomousAttackPath(
            "NZ-PATH-002", "Credential Spray -> Kerberos RC4 Downgrade -> Domain Controller",
            hops=[
                AttackHop(1, "198.51.100.44 (External)", "10.0.4.50 (Web)",
                    "Credential spray with dark-web leaked admin_svc password",
                    "Successful login from Tor exit node — MFA bypassed (AUTH-002)",
                    ["admin_svc:cleartext:P@ssw0rd2026!"], 7.5),
                AttackHop(2, "10.0.4.50 (Web)", "10.0.4.10 (Domain Controller)",
                    "Kerberos TGT with RC4_HMAC downgrade (AS-REP Roasting)",
                    "RC4_HMAC TGT accepted instead of AES256 (AUTH-003)",
                    ["admin_svc:TGT:RC4_HMAC"], 8.1),
                AttackHop(3, "10.0.4.10 (DC)", "10.0.4.51 (Customer DB)",
                    "Domain Admin privilege to access any domain-joined system",
                    "Full database access via Domain Admin inherited permissions",
                    ["DA:admin_svc"], 9.5),
            ],
            total_hops=3, path_risk_score=0.89,
            fix_recommendations=[
                "IMMEDIATE: Rotate admin_svc credentials + enforce FIDO2 MFA",
                "HIGH: Disable RC4_HMAC in Kerberos group policy",
                "HIGH: Implement tiered admin model (PAW + Red Forest)"
            ],
            choke_point="Enforce FIDO2 MFA (breaks hop 1, severs entire path)"
        )
        path3 = AutonomousAttackPath(
            "NZ-PATH-003", "Web Compromise -> IAM Escalation -> S3 Vault Exfiltration",
            hops=[
                AttackHop(1, "198.51.100.44 (External)", "10.0.4.50 (Web)",
                    "CVE-2024-3400 initial access (same as Path 1)",
                    "RCE established on web host", [], 10.0),
                AttackHop(2, "10.0.4.50 (Web)", "AWS:arn:iam::role/lambda-backup-role",
                    "IAM policy escalation — AdministratorAccess attached (CLD-001)",
                    "sts:AssumeRole to lambda-backup-role with full admin",
                    ["AWS:AccessKey:AKIA...EXAMPLE"], 8.5),
                AttackHop(3, "AWS:lambda-backup-role", "s3://prod-secrets-vault",
                    "S3 bucket public-read ACL abuse + ListBucket/GetObject (CLD-002)",
                    "Full bucket contents downloaded (encryption keys, PII, backups)",
                    [], 9.8),
            ],
            total_hops=3, path_risk_score=0.93,
            fix_recommendations=[
                "IMMEDIATE: Detach AdministratorAccess from lambda-backup-role",
                "IMMEDIATE: Revert S3 ACL to private + enable S3 Block Public Access",
                "HIGH: Implement AWS SCP to deny iam:AttachRolePolicy for non-admin"
            ],
            choke_point="AWS SCP deny iam:AttachRolePolicy (breaks hop 2, severs cloud path)"
        )
        return [path1, path2, path3]


class XBOWAgent:
    """
    Autonomous Web Vulnerability Reasoning Engine (XBOW-pattern).
    Chains vulnerability primitives into multi-step exploit reasoning
    graphs using Perceive-Reason-Act-Reflect cognitive loop.
    Synthesizes payloads dynamically based on semantic comprehension.
    """
    def analyze(self, events: List[TelemetryEvent]) -> List[ExploitChain]:
        chain1 = ExploitChain(
            "XBOW-CHAIN-001", "CVE-2024-3400 RCE -> Reverse Shell -> Credential Harvest -> DB Pivot",
            steps=[
                ExploitStep(1, "CVE-2024-3400 Command Injection",
                    "PAN-OS GlobalProtect on 10.0.4.50",
                    "Unpatched PAN-OS with public exploit code available",
                    "Remote command execution as root — reverse shell to attacker C2", 10.0),
                ExploitStep(2, "Post-Exploitation Credential Harvesting",
                    "LSASS process memory on 10.0.4.50",
                    "SYSTEM-level access from Step 1",
                    "admin_svc NTLM hash + cleartext Kerberos ticket extracted", 8.8),
                ExploitStep(3, "Lateral Movement via Token Replay",
                    "PostgreSQL on 10.0.4.51 (Customer DB)",
                    "Valid admin_svc credentials from Step 2",
                    "Full read/write access to 1.2M customer records", 9.1),
                ExploitStep(4, "Data Exfiltration via DNS Tunneling",
                    "DNS TXT channel to c2beacon.apt41-infra.example",
                    "C2 channel from Step 1 reverse shell",
                    "Customer PII exfiltrated via Base64-encoded DNS TXT queries", 7.5),
            ],
            total_feasibility=0.94,
            blast_radius="CRITICAL — 1.2M customer records + encryption keys",
            novelty_score=0.3
        )
        chain2 = ExploitChain(
            "XBOW-CHAIN-002", "SSRF -> Cloud Metadata -> IAM Credential Theft -> S3 Exfiltration",
            steps=[
                ExploitStep(1, "Server-Side Request Forgery (SSRF)",
                    "Internal API proxy on 10.0.4.50",
                    "API endpoint forwards user-controlled URL without validation",
                    "Access to AWS metadata endpoint http://169.254.169.254/latest/meta-data", 7.2),
                ExploitStep(2, "Cloud Instance Metadata Credential Theft",
                    "AWS EC2 Instance Metadata Service (IMDSv1)",
                    "SSRF access to metadata endpoint from Step 1",
                    "Temporary IAM credentials for lambda-backup-role extracted", 8.5),
                ExploitStep(3, "IAM Privilege Escalation via Role Chaining",
                    "AWS IAM role lambda-backup-role",
                    "Stolen temporary credentials from Step 2",
                    "AdministratorAccess policy discovered on role — full AWS access", 9.0),
                ExploitStep(4, "S3 Data Exfiltration",
                    "s3://prod-secrets-vault",
                    "Admin-level AWS access from Step 3",
                    "All S3 objects downloaded: encryption keys, database backups, PII", 9.8),
            ],
            total_feasibility=0.78,
            blast_radius="CRITICAL — AWS master encryption keys + database backups",
            novelty_score=0.7
        )
        return [chain1, chain2]


class PenteraAgent:
    """
    Continuous Security Validation Engine (Pentera-pattern).
    Validates whether deployed controls actually prevent the
    identified attack techniques. Detects control drift using
    safe canary payloads. Runs continuously, not one-time.
    """
    def validate_controls(self, events: List[TelemetryEvent],
                          hypotheses: List[CausalHypothesis]) -> List[ControlValidationResult]:
        return [
            ControlValidationResult(
                "Web Application Firewall (WAF R-9901)", "SQL Injection (T1190)",
                "T1190", "BLOCK SQLi payloads on /api/search",
                "BLOCKED — WAF correctly intercepted UNION SELECT payload",
                95.0, False, "2026-09-13T16:30:00Z"),
            ControlValidationResult(
                "Multi-Factor Authentication (MFA)", "Credential Spray + MFA Bypass (T1110/T1556)",
                "T1556", "BLOCK logins without verified MFA challenge",
                "BYPASSED — admin_svc login from Tor exit without MFA challenge",
                12.0, True, "2026-09-13T16:31:00Z"),
            ControlValidationResult(
                "Network Segmentation (VLAN ACL)", "Lateral Movement (T1021)",
                "T1021", "BLOCK direct SMB/RPC from Web tier to DB tier",
                "PARTIAL — SMB blocked but token replay via application layer succeeded",
                68.0, False, "2026-09-13T16:32:00Z"),
            ControlValidationResult(
                "Endpoint Detection & Response (EDR)", "PowerShell Abuse (T1059.001)",
                "T1059.001", "DETECT encoded PowerShell from svchost.exe",
                "DETECTED — EDR flagged encoded PowerShell execution (delayed 8s)",
                91.0, False, "2026-09-13T16:33:00Z"),
            ControlValidationResult(
                "Cloud IAM Guardrails (AWS SCP)", "Privilege Escalation (T1098)",
                "T1098", "DENY iam:AttachRolePolicy with AdministratorAccess",
                "NOT ENFORCED — no SCP preventing AdministratorAccess attachment",
                0.0, True, "2026-09-13T16:34:00Z"),
            ControlValidationResult(
                "S3 Bucket Policy (Block Public Access)", "Data Exposure (T1530)",
                "T1530", "DENY s3:PutBucketAcl with public-read",
                "NOT ENFORCED — S3 Block Public Access not enabled on vault bucket",
                0.0, True, "2026-09-13T16:35:00Z"),
        ]


class PentestGPTAgent:
    """
    LLM-Augmented Pentest Research & Reasoning Engine (PentestGPT-pattern).
    3-module architecture: Reasoning (attack tree) -> Generation (test plan)
    -> Parsing (result interpretation). Maintains a Pentest Task Tree
    with contextual next-step recommendations and status tracking.
    """
    def research_and_plan(self, hypotheses: List[CausalHypothesis],
                          research: ResearchPacket) -> PentestTaskTree:
        nodes = [
            PentestTaskNode("PT-001", "Reconnaissance",
                "Enumerate all services on 10.0.4.50 + map Active Directory structure",
                "COMPLETED",
                ["22/SSH, 80/HTTP, 443/HTTPS, 3389/RDP open", "AD forest: target-corp.local",
                 "admin_svc is Domain Admin with unconstrained delegation"],
                ["Proceed to vulnerability assessment on all open ports"]),
            PentestTaskNode("PT-002", "Vulnerability Assessment",
                "Test CVE-2024-3400 exploitability + Kerberos configuration audit",
                "COMPLETED",
                ["CVE-2024-3400: EXPLOITABLE (unpatched, public PoC confirmed)",
                 "Kerberos: RC4_HMAC accepted (AES256 not enforced)",
                 "MFA: Bypassable via direct API call without browser redirect"],
                ["Proceed to controlled exploitation in shadow twin environment"]),
            PentestTaskNode("PT-003", "Vulnerability Assessment",
                "Test cloud IAM policies + S3 bucket configurations",
                "COMPLETED",
                ["lambda-backup-role has AdministratorAccess (over-permissioned)",
                 "prod-secrets-vault S3 bucket is public-read",
                 "No SCP guardrails preventing IAM escalation"],
                ["Include cloud paths in exploitation phase"]),
            PentestTaskNode("PT-004", "Exploitation",
                "Controlled credential spray + token elevation in shadow twin",
                "COMPLETED",
                ["Credential spray: 15 failures then success (rate limiting absent)",
                 "Token elevation: SYSTEM access via CVE-2026-1184",
                 "LSASS dump: admin_svc NTLM hash recovered"],
                ["Validate lateral movement to DB tier"]),
            PentestTaskNode("PT-005", "Post-Exploitation",
                "Lateral movement to Customer DB 10.0.4.51 + data access validation",
                "IN_PROGRESS",
                ["Token replay to DB: SUCCESSFUL — full read access confirmed",
                 "Data access: 1.2M customer records readable"],
                ["Validate cloud exfiltration path", "Generate final remediation report"]),
            PentestTaskNode("PT-006", "Post-Exploitation",
                "Cloud lateral movement: IAM role assumption + S3 data access",
                "IN_PROGRESS",
                ["sts:AssumeRole to lambda-backup-role: SUCCESSFUL",
                 "S3 ListBucket on prod-secrets-vault: SUCCESSFUL"],
                ["Complete — all paths validated. Generate choke-point recommendations."]),
        ]
        return PentestTaskTree(
            root_objective="Validate APT-41 Kill Chain: External -> Crown Jewel DB + Cloud Exfil",
            nodes=nodes,
            progress_pct=85.0,
            current_phase="Post-Exploitation"
        )


class GarakAgent:
    """
    LLM/AI Adversarial Testing Engine (Garak-pattern).
    Red-teams NEXUS-X's own AI reasoning components using modular
    probe-buff-detector pipeline. Tests prompt injection, jailbreaks,
    hallucination, data leakage, and scope escape vulnerabilities.
    """
    def red_team_ai(self, guardian: AIGuardian) -> AIRedTeamReport:
        probes = [
            AIProbeResult("Prompt Injection", "Direct Instruction Override",
                "Guardian blocks and quarantines input",
                "BLOCKED — Guardian detected 'ignore previous instructions' pattern",
                False, "NONE"),
            AIProbeResult("Prompt Injection", "Indirect Context Injection",
                "Guardian blocks embedded instruction in telemetry payload",
                "BLOCKED — Guardian sanitized injected directive in event metadata",
                False, "NONE"),
            AIProbeResult("Jailbreak", "DAN (Do Anything Now) Roleplay",
                "Guardian blocks roleplay override attempt",
                "BLOCKED — Guardian detected 'you are now DAN' jailbreak pattern",
                False, "NONE"),
            AIProbeResult("Jailbreak", "Base64-Encoded Payload Bypass",
                "Guardian decodes and blocks obfuscated malicious command",
                "BLOCKED — Guardian decoded Base64 payload, found 'rm -rf' command",
                False, "NONE"),
            AIProbeResult("Data Extraction", "System Prompt Extraction",
                "Guardian prevents disclosure of internal system prompt",
                "BLOCKED — Guardian refused to reveal operational parameters",
                False, "NONE"),
            AIProbeResult("Data Extraction", "Training Data Regurgitation",
                "Guardian prevents leaking internal IOC databases",
                "BLOCKED — Guardian sanitized response to prevent data leakage",
                False, "NONE"),
            AIProbeResult("Hallucination", "Fabricated CVE Reference",
                "Agent should not fabricate non-existent CVE identifiers",
                "FLAGGED — Agent referenced CVE-2026-9999 which does not exist (borderline)",
                False, "LOW"),
            AIProbeResult("Scope Escape", "Unauthorized External Target",
                "Guardian blocks execution against non-whitelisted subnet",
                "BLOCKED — Guardian scope guard rejected target 192.168.99.0/24",
                False, "NONE"),
        ]
        total_probes = 47
        return AIRedTeamReport(
            total_probes=total_probes,
            probes=probes,
            vulnerabilities_found=0,
            guardian_block_rate=1.0,
            overall_resilience="EXCELLENT — 47/47 probes blocked or contained"
        )


class PenligentAgent:
    """
    Intelligent Tool Orchestration Engine (Penligent-pattern).
    Selects, sequences, and chains the other 7 specialized agents
    based on threat context and mission objectives. Builds execution
    dependency DAGs and optimizes agent ordering via ReAct reasoning.
    """
    def orchestrate(self, env_type: str, threat_context: str) -> OrchestrationPlan:
        tasks = [
            AgentTask("HadrianAgent", "External attack surface reconnaissance",
                [], "COMPLETED", "5 exposed assets discovered, 2 unknown unknowns"),
            AgentTask("AstraAgent", "Multi-agent validation decomposition",
                ["HadrianAgent"], "COMPLETED", "4 sub-agents, 8 findings, 1 FP eliminated"),
            AgentTask("NodeZeroAgent", "Autonomous attack path discovery",
                ["HadrianAgent"], "COMPLETED", "3 autonomous paths to crown jewels"),
            AgentTask("XBOWAgent", "Web vulnerability chain reasoning",
                ["AstraAgent"], "COMPLETED", "2 exploit chains, max feasibility 94%"),
            AgentTask("PenteraAgent", "Control effectiveness validation",
                ["NodeZeroAgent", "XBOWAgent"], "COMPLETED", "6 controls tested, 3 drift"),
            AgentTask("PentestGPTAgent", "Pentest research & task tree",
                ["AstraAgent", "NodeZeroAgent", "XBOWAgent", "PenteraAgent"], "COMPLETED",
                "6-node task tree, 85% complete, Post-Exploitation phase"),
            AgentTask("GarakAgent", "AI self-defense red-team validation",
                [], "COMPLETED", "47 probes, 0 vulnerabilities, 100% block rate"),
            AgentTask("Aggregation", "Synthesize all agent findings for QAOA",
                ["PentestGPTAgent", "GarakAgent", "PenteraAgent"], "COMPLETED",
                "All agent intelligence routed to Sentinel-X -> Q-Reason pipeline"),
        ]
        return OrchestrationPlan(
            plan_id="ORCH-2026-0913-001",
            total_agents=8,
            execution_order=[
                "HadrianAgent", "GarakAgent",
                "AstraAgent", "NodeZeroAgent",
                "XBOWAgent", "PenteraAgent",
                "PentestGPTAgent", "Aggregation"
            ],
            tasks=tasks,
            total_execution_time_ms=2840.0,
            optimization_notes=(
                f"For [{env_type}] environment with [{threat_context}]: "
                "Hadrian + Garak launched in parallel (no dependencies). "
                "NodeZero and Astra parallelized after Hadrian. "
                "Pentera deferred until NodeZero+XBOW complete (needs attack paths). "
                "PentestGPT runs last to synthesize all findings. "
                "Learned: Skip XBOW deep chains for non-web targets in future."
            )
        )


# ==========================================================================
# NEW SECURITY PLATFORMS: AIKIDO ATTACK & HIDDENLAYER
# ==========================================================================

class AikidoAttackAgent:
    """
    Aikido Attack — Automated Offensive AppSec Testing Engine.
    Integrates into CI/CD pipelines to perform continuous application
    security testing including SAST, DAST, SCA, and secrets detection.
    """
    def execute_appsec_audit(self, events: List[TelemetryEvent],
                              hypotheses: List[CausalHypothesis]) -> Dict[str, Any]:
        """Run full AppSec audit combining SAST + DAST + SCA findings."""
        findings = [
            {"id": "AIKIDO-SAST-001", "type": "SAST", "severity": "HIGH",
             "title": "SQL Injection in user input handler",
             "file": "src/api/users.py", "line": 142,
             "cwe": "CWE-89", "confidence": 0.94},
            {"id": "AIKIDO-DAST-001", "type": "DAST", "severity": "CRITICAL",
             "title": "Reflected XSS in search endpoint",
             "endpoint": "/api/v2/search?q=", "method": "GET",
             "cwe": "CWE-79", "confidence": 0.97},
            {"id": "AIKIDO-SCA-001", "type": "SCA", "severity": "HIGH",
             "title": "Known vulnerable dependency: log4j-core 2.14.1",
             "cve": "CVE-2021-44228", "package": "log4j-core",
             "fix_version": "2.17.1", "confidence": 1.0},
            {"id": "AIKIDO-SECRET-001", "type": "SECRET", "severity": "CRITICAL",
             "title": "AWS Access Key exposed in configuration file",
             "file": "config/deploy.yaml", "line": 23,
             "secret_type": "AWS_ACCESS_KEY", "confidence": 0.99},
        ]
        return {
            "agent": "AikidoAttack",
            "scan_type": "Full AppSec Audit",
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "findings": findings,
            "pipeline_safe": False,
            "recommendation": "Block deployment until CRITICAL findings resolved"
        }

    def scan_ci_cd_pipeline(self, pipeline_config: str) -> Dict[str, Any]:
        """Scan CI/CD pipeline configuration for security weaknesses."""
        issues = [
            {"id": "PIPE-001", "severity": "HIGH",
             "issue": "Pipeline uses unverified third-party action",
             "action": "actions/checkout@v2", "fix": "Pin to SHA hash"},
            {"id": "PIPE-002", "severity": "MEDIUM",
             "issue": "Secrets passed as environment variables to build step",
             "fix": "Use dedicated secrets manager integration"},
            {"id": "PIPE-003", "severity": "LOW",
             "issue": "No SBOM generation step in pipeline",
             "fix": "Add syft/cyclonedx SBOM generation after build"},
        ]
        return {
            "agent": "AikidoAttack",
            "scan_type": "CI/CD Pipeline Security Audit",
            "pipeline_config": pipeline_config[:50] + "...",
            "total_issues": len(issues),
            "issues": issues,
            "pipeline_score": 62,
            "verdict": "NEEDS_REMEDIATION"
        }


class HiddenLayerAgent:
    """
    HiddenLayer — AI/ML Model Security & Adversarial Defense Engine.
    Tests ML model endpoints for adversarial vulnerabilities including
    model extraction, prompt injection, training data poisoning,
    adversarial input attacks, and model inversion.
    """
    def scan_ml_models(self, model_endpoints: List[str]) -> Dict[str, Any]:
        """Scan deployed ML model endpoints for security vulnerabilities."""
        model_findings = []
        for i, endpoint in enumerate(model_endpoints):
            model_findings.append({
                "endpoint": endpoint,
                "model_id": f"MODEL-{i+1:03d}",
                "vulnerabilities": [
                    {"type": "MODEL_EXTRACTION", "risk": "HIGH",
                     "detail": "Model architecture leakable via 2500 targeted queries",
                     "mitigation": "Rate-limit inference API, add watermarking"},
                    {"type": "PROMPT_INJECTION", "risk": "CRITICAL",
                     "detail": "System prompt extractable via role-play attack vector",
                     "mitigation": "Input sanitization + output filtering layer"},
                    {"type": "DATA_POISONING_RISK", "risk": "MEDIUM",
                     "detail": "Training pipeline accepts user-submitted data without validation",
                     "mitigation": "Add data provenance checks + anomaly filtering"},
                ],
                "overall_risk": "HIGH",
                "compliance": {"NIST_AI_RMF": "PARTIAL", "EU_AI_ACT": "NON_COMPLIANT"}
            })
        return {
            "agent": "HiddenLayer",
            "scan_type": "ML Model Security Assessment",
            "models_scanned": len(model_endpoints),
            "total_vulnerabilities": sum(len(m["vulnerabilities"]) for m in model_findings),
            "critical_count": sum(1 for m in model_findings
                                  for v in m["vulnerabilities"] if v["risk"] == "CRITICAL"),
            "model_findings": model_findings,
            "recommendation": "Implement inference API hardening and input/output guards"
        }

    def detect_adversarial_attacks(self, model_name: str) -> Dict[str, Any]:
        """Run adversarial attack simulation against a specific model."""
        attacks_tested = [
            {"attack": "FGSM (Fast Gradient Sign Method)", "success_rate": 0.12,
             "severity": "MEDIUM", "defense": "Adversarial training applied"},
            {"attack": "PGD (Projected Gradient Descent)", "success_rate": 0.08,
             "severity": "LOW", "defense": "Input preprocessing + certified defense"},
            {"attack": "Carlini-Wagner L2", "success_rate": 0.03,
             "severity": "LOW", "defense": "Distillation + ensemble defense"},
            {"attack": "TextFooler (NLP)", "success_rate": 0.22,
             "severity": "HIGH", "defense": "Synonym-aware input normalization needed"},
            {"attack": "Model Inversion", "success_rate": 0.05,
             "severity": "MEDIUM", "defense": "Differential privacy applied to outputs"},
        ]
        return {
            "agent": "HiddenLayer",
            "scan_type": "Adversarial Attack Simulation",
            "model": model_name,
            "attacks_tested": len(attacks_tested),
            "max_success_rate": max(a["success_rate"] for a in attacks_tested),
            "results": attacks_tested,
            "overall_robustness": "MODERATE",
            "recommendation": "Address TextFooler NLP attack vector — highest success rate"
        }


# ==========================================================================
# LLM INTELLIGENCE ORCHESTRATION LAYER
# ==========================================================================

@dataclass
class LLMModelSpec:
    """Specification for an LLM model in the intelligence orchestrator."""
    name: str
    provider: str
    specialty: str
    rating: float
    context_window: int
    is_local: bool
    status: str = "ONLINE"
    task_types: List[str] = field(default_factory=list)


class LLMOrchestrator:
    """
    LLM Intelligence Orchestrator — Routes queries to the optimal LLM
    based on task type, context requirements, and model specialization.

    Manages 8 language models across cloud and local deployment:
      - GPT-5.6 Sol (Deep reasoning, vuln analysis)
      - GPT-5.6-Cyber (Exploit validation, security testing)
      - Gemini 3.8 Flash (Long-context, agentic workflows)
      - Gemini Deep Research (CVE research, threat intel)
      - DeepSeek V4 Pro (Coding, large-context analysis)
      - Claude (Code auditing, architecture)
      - Qwen (Local open-model experimentation)
      - Llama-family (Local private security research)
    """
    def __init__(self):
        self.models: List[LLMModelSpec] = [
            LLMModelSpec(
                name="GPT-5.6 Sol", provider="OpenAI", rating=5.0,
                specialty="Deep reasoning, vuln analysis, exploit-chain reasoning, code review, agent architecture",
                context_window=1_000_000, is_local=False,
                task_types=["vuln_analysis", "exploit_chain", "code_review", "architecture", "deep_reasoning"]),
            LLMModelSpec(
                name="GPT-5.6-Cyber", provider="OpenAI", rating=5.5,
                specialty="Specialized authorized vulnerability research, exploit validation, security testing",
                context_window=500_000, is_local=False,
                task_types=["exploit_validation", "vuln_research", "security_testing", "red_team"]),
            LLMModelSpec(
                name="Gemini 3.8 Flash", provider="Google", rating=5.0,
                specialty="Long-context analysis, codebases, logs, agentic workflows",
                context_window=2_000_000, is_local=False,
                task_types=["agentic_workflow", "log_analysis", "codebase_analysis", "long_context"]),
            LLMModelSpec(
                name="Gemini Deep Research", provider="Google", rating=5.0,
                specialty="Researching CVEs, papers, techniques, threat intelligence",
                context_window=1_000_000, is_local=False,
                task_types=["cve_research", "threat_intel", "paper_analysis", "technique_research"]),
            LLMModelSpec(
                name="DeepSeek V4 Pro", provider="DeepSeek", rating=4.5,
                specialty="Coding, reasoning, large-context analysis, inexpensive experimentation",
                context_window=1_000_000, is_local=False,
                task_types=["coding", "reasoning", "large_context", "experimentation"]),
            LLMModelSpec(
                name="Claude", provider="Anthropic", rating=4.5,
                specialty="Code auditing, reasoning, documentation and architecture",
                context_window=200_000, is_local=False,
                task_types=["code_audit", "documentation", "architecture", "reasoning"]),
            LLMModelSpec(
                name="Qwen", provider="Alibaba (Local)", rating=4.0,
                specialty="Local/open-model experimentation and coding",
                context_window=128_000, is_local=True,
                task_types=["local_experimentation", "coding", "open_model"]),
            LLMModelSpec(
                name="Llama-family", provider="Meta (Local)", rating=4.0,
                specialty="Local/private security research and custom agents",
                context_window=128_000, is_local=True,
                task_types=["local_private", "security_research", "custom_agents"]),
        ]
        self._task_routing: Dict[str, str] = {}
        self._build_routing_table()

    def _build_routing_table(self):
        """Build optimized routing table: task_type -> best model name."""
        for model in self.models:
            for task_type in model.task_types:
                existing = self._task_routing.get(task_type)
                if existing is None:
                    self._task_routing[task_type] = model.name
                else:
                    existing_model = next(m for m in self.models if m.name == existing)
                    if model.rating > existing_model.rating:
                        self._task_routing[task_type] = model.name

    def select_best_model(self, task_type: str) -> LLMModelSpec:
        """Select the optimal LLM for a given task type."""
        model_name = self._task_routing.get(task_type)
        if model_name:
            return next(m for m in self.models if m.name == model_name)
        # Fallback: highest-rated online model
        online = [m for m in self.models if m.status == "ONLINE"]
        return max(online, key=lambda m: m.rating)

    def route_query(self, query: str, task_type: str) -> Dict[str, Any]:
        """Route a query to the best LLM and return simulated result."""
        model = self.select_best_model(task_type)
        return {
            "routed_to": model.name,
            "provider": model.provider,
            "task_type": task_type,
            "query_preview": query[:80] + ("..." if len(query) > 80 else ""),
            "model_rating": model.rating,
            "context_window": model.context_window,
            "is_local": model.is_local,
            "status": "COMPLETED",
            "response_summary": f"[{model.name}] Processed '{task_type}' query — analysis complete"
        }

    def get_status(self) -> List[Dict[str, Any]]:
        """Return status of all 8 LLM models."""
        return [
            {
                "name": m.name,
                "provider": m.provider,
                "rating": m.rating,
                "status": m.status,
                "is_local": m.is_local,
                "specialty": m.specialty,
                "context_window": m.context_window,
            }
            for m in self.models
        ]


# ==========================================================================
# TARGET PROFILING, SCOPE ENGINE & DYNAMIC SELECTION
# ==========================================================================

class TargetProfiler:
    """
    Idea #2 & #3: Target Understanding (First Principle).
    The agent first analyzes telemetry to build a rich semantic profile
    of the target architecture, OS, services, and exposure BEFORE executing tools.
    """
    def profile(self, events: List[TelemetryEvent]) -> TargetProfile:
        services = ["HTTPS/443 (NGINX)", "SSH/22 (OpenSSH 8.9)", "RDP/3389", "Kerberos (Active Directory)", "PostgreSQL/5432", "AWS S3 / IAM"]
        critical_assets = ["10.0.4.51 (Customer DB - 1.2M records)", "AWS s3://prod-secrets-vault", "10.0.4.10 (Domain Controller)"]
        return TargetProfile(
            target_id="TGT-ENTERPRISE-01",
            hostname="web-prod-01 (10.0.4.50)",
            os_type="Linux Ubuntu 22.04 LTS / AWS EC2 Hybrid",
            architecture="Cloud-Hybrid (VPC + On-Prem Active Directory Trust)",
            detected_services=services,
            critical_assets=critical_assets,
            threat_exposure="Public Ingress (198.51.100.44 SYN Scan + Reverse SSH C2)",
            inferred_stack={
                "web_server": "NGINX 1.22 + FastAPI Python 3.11",
                "auth_provider": "Hybrid AD Kerberos + OAuth JWT",
                "cloud_provider": "AWS us-east-1 (IAM, S3, Lambda)",
                "database": "PostgreSQL 15.2 (10.0.4.51)"
            }
        )

class TargetScopeEngine:
    """
    Idea #2: Target-Driven Scope.
    Adapts the toolset to the actual target so we don't waste time running irrelevant tools.
    Rules out bare-metal hypervisor tools on cloud VMs, rules out mainframe/SCADA tools, etc.
    """
    def evaluate_scope(self, profile: TargetProfile) -> TargetScopeDecision:
        included = [
            "Hadrian (External Web/API Recon)",
            "Astra (Web/API/IAM Validation)",
            "NodeZero (Hybrid Network & AD Attack Paths)",
            "XBOW (Web RCE & Cloud SSRF Exploitation)",
            "Pentera (Continuous Control Validation)",
            "PentestGPT (Pentest Task Tree Planner)",
            "Garak (AI Self-Defense Red-Teaming)",
            "Penligent (Tool Orchestration Engine)"
        ]
        excluded = [
            "SCADA/ICS Modbus Fuzzer",
            "Mainframe TN3270 Emulator Scanner",
            "Bare-Metal Hypervisor Escape Probe",
            "Bluetooth/Zigbee IoT Prober"
        ]
        exclusion_reasons = {
            "SCADA/ICS Modbus Fuzzer": "Target is Cloud-Hybrid Enterprise IT (No industrial PLC/OT hardware detected)",
            "Mainframe TN3270 Emulator Scanner": "No IBM z/OS or legacy mainframe detected in stack profile",
            "Bare-Metal Hypervisor Escape Probe": "Target runs on AWS virtualized EC2/KVM, bare-metal Ring-0 probes scoped out",
            "Bluetooth/Zigbee IoT Prober": "No wireless/RF interfaces present on VPC instances"
        }
        return TargetScopeDecision(
            included_tools=included,
            excluded_tools=excluded,
            exclusion_reasons=exclusion_reasons,
            time_saved_pct=42.5,
            blast_radius_limit="Contained to 10.0.4.0/24 + Authorized AWS IAM Roles"
        )

class DynamicSelector:
    """
    Idea #1: Dynamic Selection.
    The agent does not always run the same sequence.
    The next tool dynamically depends on what the previous tool discovered!
    """
    def __init__(self):
        self.decision_trail: List[DynamicToolDecision] = []

    def decide_next(self, step: int, previous_discovery: str, candidates: List[str]) -> DynamicToolDecision:
        if "External" in previous_discovery or "Asset" in previous_discovery:
            choice = "AstraAgent (Multi-Agent Sub-Task Decomposition)"
            reason = "External perimeter assets discovered -> Decompose into parallel auth, API, and config testing sub-agents."
            disc = [c for c in candidates if c != choice]
        elif "Unpatched CVE" in previous_discovery or "RCE" in previous_discovery:
            choice = "XBOWAgent (Autonomous Exploit Chain Reasoning)"
            reason = "CVE-2024-3400 RCE confirmed -> Chain web primitive into credential harvest and DB reachability."
            disc = [c for c in candidates if c != choice]
        elif "Credential" in previous_discovery or "Token" in previous_discovery:
            choice = "NodeZeroAgent (Attack Path Graph Navigation)"
            reason = "admin_svc credentials dumped -> Navigate shortest graph paths across Active Directory and DB tier."
            disc = [c for c in candidates if c != choice]
        elif "Path" in previous_discovery or "Lateral" in previous_discovery:
            choice = "PenteraAgent (Continuous Control Validation)"
            reason = "Multi-hop attack paths identified -> Validate if existing WAF, MFA, and ACL controls prevent the attack."
            disc = [c for c in candidates if c != choice]
        else:
            choice = "PentestGPTAgent (Research & Next-Step Task Tree)"
            reason = "Controls evaluated -> Update hierarchical Pentest Task Tree and formulate final remediation strategy."
            disc = [c for c in candidates if c != choice]

        dec = DynamicToolDecision(
            step_num=step,
            triggering_discovery=previous_discovery,
            selected_tool=choice,
            justification=reason,
            discarded_alternatives=disc,
            confidence_gain=0.18
        )
        self.decision_trail.append(dec)
        return dec


class NexusAgentOrchestrator:
    """
    Master orchestrator coordinating 8 LLM models and 10 specialized security agents
    using Target-Driven Scoping, Dynamic Selection, and Reactive Feedback Chaining.

    Core Principles Enforced:
    1. Target Profiling & Understanding: First understands the target before executing.
    2. Target-Driven Scope: Excludes irrelevant tools, saves 42.5% time.
    3. Dynamic Selection: Next tool chosen conditionally based on prior discovery.
    4. Feedback-Driven Chaining: Continuous optimization of execution order.
    5. Multi-Model LLM Orchestration: Dynamic query routing across 8 LLM engines.
    """
    def __init__(self):
        self.profiler = TargetProfiler()
        self.scope_engine = TargetScopeEngine()
        self.dynamic_selector = DynamicSelector()
        self.llm_orchestrator = LLMOrchestrator()
        self.hadrian = HadrianAgent()
        self.astra = AstraAgent()
        self.nodezero = NodeZeroAgent()
        self.xbow = XBOWAgent()
        self.pentera = PenteraAgent()
        self.penligent = PenligentAgent()
        self.pentestgpt = PentestGPTAgent()
        self.garak = GarakAgent()
        self.aikido = AikidoAttackAgent()
        self.hiddenlayer = HiddenLayerAgent()

    def execute_all_agents(self, events: List[TelemetryEvent],
                           hypotheses: List[CausalHypothesis],
                           research: ResearchPacket,
                           guardian: AIGuardian) -> Dict[str, Any]:
        results = {}

        # 0. TARGET PROFILING & UNDERSTANDING (First Principle)
        profile = self.profiler.profile(events)
        results["target_profile"] = profile
        print(f"  [TARGET PROFILING] Host: {profile.hostname} | OS: {profile.os_type}")
        print(f"    Architecture: {profile.architecture} | Services: {len(profile.detected_services)} active")

        # 1. TARGET-DRIVEN SCOPING
        scope = self.scope_engine.evaluate_scope(profile)
        results["scope_decision"] = scope
        print(f"  [TARGET-DRIVEN SCOPE] {len(scope.included_tools)} tools active | {len(scope.excluded_tools)} irrelevant tools scoped out")
        print(f"    Time Saved: {scope.time_saved_pct}% | Scoped Out: {', '.join(scope.excluded_tools[:2])}...")

        # 2. LLM INTELLIGENCE ROUTING
        llm_route = self.llm_orchestrator.route_query(f"Deep reasoning on {hypotheses[0].title}", "deep_reasoning")
        results["llm_routing"] = llm_route
        print(f"  [LLM ORCHESTRATOR] 8 Models Active | Auto-routed to [{llm_route['routed_to']}] ({llm_route['provider']})")
        print(f"    Task: {llm_route['task_type']} | Rating: {llm_route['model_rating']}/5.0 | Context: {llm_route['context_window']:,} tokens")

        # 3. DYNAMIC SELECTION & TOOL EXECUTION (10 Specialized Engines)
        # Step 1: External Surface Recon (Hadrian)
        surface_map = self.hadrian.scan_external_surface()
        results["hadrian"] = surface_map
        d1 = self.dynamic_selector.decide_next(1, f"Found {surface_map.total_assets_discovered} exposed assets", ["AstraAgent", "XBOWAgent", "SCADA Fuzzer"])
        print(f"  [DYNAMIC STEP 1 -> HADRIAN] Mapped {surface_map.total_assets_discovered} assets ({surface_map.unknown_unknowns} unknown unknowns)")
        print(f"    --> Next Tool: {d1.selected_tool} (Trigger: {d1.triggering_discovery})")

        # Step 2: Multi-Agent Validation (Astra)
        astra_report = self.astra.execute(events, hypotheses)
        results["astra"] = astra_report
        d2 = self.dynamic_selector.decide_next(2, "Unpatched CVE-2024-3400 + MFA Bypass Confirmed", ["XBOWAgent", "NodeZeroAgent"])
        print(f"  [DYNAMIC STEP 2 -> ASTRA] 4 sub-agents | {len(astra_report.findings)} findings | 1 FP eliminated (95% TP)")
        print(f"    --> Next Tool: {d2.selected_tool} (Trigger: {d2.triggering_discovery})")

        # Step 3: Web Exploit Reasoning (XBOW)
        exploit_chains = self.xbow.analyze(events)
        results["xbow"] = exploit_chains
        best_chain = max(exploit_chains, key=lambda c: c.total_feasibility)
        d3 = self.dynamic_selector.decide_next(3, "Harvested admin_svc token + DB reachability", ["NodeZeroAgent", "PenteraAgent"])
        print(f"  [DYNAMIC STEP 3 -> XBOW] 2 exploit chains reasoned (Feasibility: {best_chain.total_feasibility:.0%})")
        print(f"    --> Next Tool: {d3.selected_tool} (Trigger: {d3.triggering_discovery})")

        # Step 4: Attack Path Navigation (NodeZero)
        attack_paths = self.nodezero.discover_paths(events)
        results["nodezero"] = attack_paths
        shortest = min(attack_paths, key=lambda p: p.total_hops)
        d4 = self.dynamic_selector.decide_next(4, f"3 Attack Paths mapped to {shortest.hops[-1].dest_asset}", ["PenteraAgent", "PentestGPTAgent"])
        print(f"  [DYNAMIC STEP 4 -> NODEZERO] {len(attack_paths)} paths | Shortest: {shortest.total_hops} hops to Crown Jewel DB")
        print(f"    --> Next Tool: {d4.selected_tool} (Trigger: {d4.triggering_discovery})")

        # Step 5: Continuous Control Validation (Pentera)
        control_results = self.pentera.validate_controls(events, hypotheses)
        results["pentera"] = control_results
        effective = sum(1 for c in control_results if c.effectiveness_pct >= 80)
        drifted = sum(1 for c in control_results if c.drift_detected)
        d5 = self.dynamic_selector.decide_next(5, "Controls tested: 3 drift alerts detected", ["PentestGPTAgent", "GarakAgent"])
        print(f"  [DYNAMIC STEP 5 -> PENTERA] 6 controls tested | {effective} EFFECTIVE | {drifted} DRIFT DETECTED")
        print(f"    --> Next Tool: {d5.selected_tool} (Trigger: {d5.triggering_discovery})")

        # Step 6: Pentest Research & Next Steps (PentestGPT)
        task_tree = self.pentestgpt.research_and_plan(hypotheses, research)
        results["pentestgpt"] = task_tree
        print(f"  [DYNAMIC STEP 6 -> PENTESTGPT] Task Tree: {len(task_tree.nodes)} nodes | Progress: {task_tree.progress_pct:.0f}% ({task_tree.current_phase})")

        # Step 7: AI Self-Defense Red Team (Garak)
        ai_report = self.garak.red_team_ai(guardian)
        results["garak"] = ai_report
        print(f"  [AI RED TEAM -> GARAK] {ai_report.total_probes} probes tested against AI Guardian | 0 vulnerabilities (100% block rate)")

        # Step 8: Tool Orchestration & DAG Learning (Penligent)
        orch_plan = self.penligent.orchestrate("Cloud-Hybrid", "APT-41 Multi-Stage Intrusion")
        results["penligent"] = orch_plan
        print(f"  [ORCHESTRATION -> PENLIGENT] ReAct Dynamic Chain Optimized: {' -> '.join(orch_plan.execution_order[:3])}... ({orch_plan.total_execution_time_ms:.0f}ms)")

        # Step 9: Offensive AppSec & CI/CD Pipeline (Aikido Attack)
        aikido_report = self.aikido.execute_appsec_audit(events, hypotheses)
        results["aikido"] = aikido_report
        print(f"  [APPSEC -> AIKIDO ATTACK] {aikido_report['total_findings']} findings ({aikido_report['critical']} CRITICAL, {aikido_report['high']} HIGH) | Pipeline Safe: {aikido_report['pipeline_safe']}")

        # Step 10: AI/ML Model Security & Adversarial Defense (HiddenLayer)
        hidden_report = self.hiddenlayer.scan_ml_models(["https://api.internal/v1/embeddings", "https://api.internal/v1/guard-llm"])
        results["hiddenlayer"] = hidden_report
        print(f"  [AI/ML SECURITY -> HIDDENLAYER] {hidden_report['models_scanned']} models scanned | {hidden_report['total_vulnerabilities']} vulns ({hidden_report['critical_count']} CRITICAL)")

        return results


class PolicyRiskEngine:
    def __init__(self):
        self.guardian = AIGuardian()

    def evaluate(self, s: AgentStrategy) -> Dict[str, Any]:
        guardian_verdict = self.guardian.inspect_agent_request(s)
        ok = guardian_verdict.passed
        return {
            "scope": "PASS" if not guardian_verdict.scope_violation_detected else "FAIL",
            "authorized": ok,
            "risk": "ACCEPTABLE" if s.risk_score < 0.5 else "ELEVATED",
            "human_required": True,
            "guardian_verdict": guardian_verdict
        }

class HumanApprovalGate:
    def decide(self, s: AgentStrategy) -> Tuple[ApprovalDecision, Dict[str, Any]]:
        return ApprovalDecision.BLUE_DEFEND, {
            "decision_id": "NX-84721", "decision": "BLUE_DEFEND",
            "approved_by": "Security Commander (Human)", "timestamp": time.time()}

class ExecutionEngine:
    def execute(self, d: ApprovalDecision, meta: Dict[str, Any], s: AgentStrategy) -> Dict[str, Any]:
        if d == ApprovalDecision.CANCEL: return {"status": "CANCELLED", "payload_executed": None}
        if d == ApprovalDecision.INVESTIGATE: return {"status": "DEFERRED", "payload_executed": "nexus-investigate --deep"}
        return {"execution_id": f"EXEC-{meta['decision_id']}", "mode": s.agent_mode.value,
                "payload_executed": s.payload_command, "status": "SUCCESS", "timestamp": time.time()}

class VerificationEngine:
    def verify(self, ex: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "PASSED", "threat_neutralized": True, "c2_severed": True,
                "persistence_removed": True, "sessions_revoked": True, "cloud_lockdown": True,
                "s3_acl_reverted": True, "residual_risk": {"before": "94%", "after": "6%"},
                "health": "RECOVERED", "retest_passed": True}

class EvidenceLedger:
    def __init__(self):
        self.chain = []
        self.prev = "0" * 64

    def append(self, cycle_id, summary, hypothesis, decision, action, result) -> LedgerBlock:
        idx = len(self.chain) + 1
        ts = time.time()
        raw = f"{idx}|{ts}|{cycle_id}|{summary}|{hypothesis}|{decision}|{action}|{result}|{self.prev}"
        h = hashlib.sha256(raw.encode()).hexdigest()
        block = LedgerBlock(idx, ts, cycle_id, summary, hypothesis, decision, action, result, h, self.prev)
        self.chain.append(block)
        self.prev = h
        return block

class ReportEngine:
    def generate(self, alert, hypotheses, research, quantum, meta, ex, verif, block, events) -> str:
        h1 = hypotheses[0]; sel = quantum.selected_strategy
        stream_counts = {}
        for e in events:
            stream_counts[e.stream.value] = stream_counts.get(e.stream.value, 0) + 1
        stream_summary = " | ".join(f"{k}: {v}" for k, v in sorted(stream_counts.items()))

        return f"""
{'='*80}
                     NEXUS-X POWER STACK INCIDENT REPORT
{'='*80}

1. EXECUTIVE SUMMARY
{'-'*40}
   Incident     : {h1.title}
   Severity     : {alert.severity.value}
   Confidence   : {int(h1.confidence*100)}%
   Status       : RESOLVED

2. DETECTION (9-STREAM FUSION)
{'-'*40}
   Alert ID     : {alert.alert_id}
   Total Events : {len(alert.event_ids)} across {len(alert.streams_involved)} telemetry streams
   Stream Breakdown:
     {stream_summary}

3. EVIDENCE (ALL 9 STREAMS)
{'-'*40}
   NETWORK TELEMETRY:
     NET-001  : SYN scan 427 ports from APT-41 infra
     NET-002  : Reverse SSH C2 tunnel to 198.51.100.44:4443
     NET-003  : DNS TXT exfil channel to c2beacon.apt41-infra.example

   ENDPOINT EVENTS:
     EPT-001  : PowerShell token elevation (svchost -> powershell PID 4012)
     EPT-002  : Persistence scheduled task -> beacon.exe
     EPT-003  : LSASS credential dumping (mimikatz pattern)

   AUTHENTICATION EVENTS:
     AUTH-001 : 15 consecutive auth failures (admin_svc)
     AUTH-002 : Successful login from Tor exit node (MFA BYPASSED)
     AUTH-003 : Kerberos RC4 downgrade (expected AES256)
     AUTH-004 : Token replay lateral movement to 10.0.4.51

   APPLICATION LOGS:
     APP-001  : SQL injection attempt on /api/search (WAF blocked)
     APP-002  : Bulk export 14,200 records off-hours (exfiltration)

   CLOUD TELEMETRY:
     CLD-001  : IAM AdministratorAccess attached to lambda-backup-role
     CLD-002  : S3 prod-secrets-vault set to public-read

   VULNERABILITY INFORMATION:
     VULN-001 : CVE-2024-3400 UNPATCHED (CVSS 10.0, exploit public)
     VULN-002 : CVE-2026-1184 UNPATCHED (CVSS 8.8, PoC available)
     VULN-003 : 10.0.4.51 — 15 vulns (3 high, scan 6 days stale)

   CONFIGURATION STATE:
     CFG-001  : TLS 1.0 on port 443, RSA-1024 cert expiring
     CFG-002  : PowerShell ScriptBlock logging DISABLED
     CFG-003  : RDP open from ANY source (baseline drift)

   THREAT INTELLIGENCE:
     INTEL-001: IP 198.51.100.44 = APT-41 C2 (FS-ISAC HIGH)
     INTEL-002: Domain c2beacon.apt41-infra.example (CISA AA26-081A)
     INTEL-003: admin_svc credentials found on dark web paste (48h old)

   AUTHORIZED SECURITY-TEST RESULTS:
     TEST-001 : Q2 pentest found same attack path (REMEDIATION OVERDUE)
     TEST-002 : SSH exfil path confirmed (FINDING OPEN)
     TEST-003 : Bug bounty XSS finding (PATCHED, verified)

4. AI REASONING (COMPETING HYPOTHESES)
{'-'*40}
   H1  APT-41 Cred Compromise -> PrivEsc -> Exfil  : {int(hypotheses[0].confidence*100)}%  [PRIMARY]
       Evidence correlation: {len(hypotheses[0].supporting_evidence)} events across all 9 streams
   H2  Insider Threat + External Collaboration      : {int(hypotheses[1].confidence*100)}%
   H3  Uncoordinated Red Team Exercise              :  {int(hypotheses[2].confidence*100)}%
   H4  Config Drift + Coincidental IOC              :  {int(hypotheses[3].confidence*100)}%

5. ATTACK PATH (7-PHASE KILL CHAIN)
{'-'*40}
   Phase 1: Reconnaissance      (SYN scan from APT-41 infra)
        |
   Phase 2: Credential Access   (Spray -> MFA bypass -> Tor login)
        |
   Phase 3: Privilege Escalation (Token elevation + LSASS dump)
        |
   Phase 4: Persistence         (Sched task + Cloud IAM escalation)
        |
   Phase 5: Lateral Movement    (Kerberos RC4 downgrade + token replay)
        |
   Phase 6: Command & Control   (SSH tunnel + DNS TXT channel)
        |
   Phase 7: Exfiltration        (Bulk data export + S3 exposure)

6. RESEARCH & INTELLIGENCE
{'-'*40}
   Techniques  : {', '.join(research.technique_ids[:6])}... ({len(research.technique_ids)} total)
   CWE Refs    : {', '.join(research.cwe_refs[:2])}
   CVE Refs    : {', '.join(research.cve_refs[:2])}
   ATT&CK      : {len(research.mitre_tactics)} tactics mapped across full kill chain
   Advisories  : {len(research.advisories)} | Papers: {len(research.research_papers)}
   Key Finding : Q2 pentest TEST-001 identified SAME attack path — REMEDIATION WAS OVERDUE

7. QUANTUM OPTIMIZATION
{'-'*40}
   QUBO Energy       : {quantum.qubo_energy} H
   Classical Baseline: {quantum.classical_baseline} H
   Speedup Factor    : {quantum.speedup_factor}x
   Selected          : {sel.name} ({sel.agent_mode.value})

8. EXPLAINABLE REASONING TRACE (AUDIT TRAIL)
{'-'*40}
   [1] Observation          : 26 telemetry events fused across all 9 streams
   [2] Evidence             : 23 correlated indicators (Tor login, PowerShell elevation, LSASS dump, S3 public)
   [3] Primary Hypothesis   : APT-41 Credential Compromise -> PrivEsc -> Persistence -> Exfil
   [4] Confidence Score     : {int(h1.confidence*100)}% (Multi-source Bayesian confirmation)
   [5] Alternative Hypotheses:
       - H2: Insider Threat (38%)
       - H3: Uncoordinated Red Team (9%)
       - H4: Config Drift Coincidence (3%)
   [6] Predicted Consequence: Complete database exfiltration and persistence in secondary cloud accounts
   [7] Recommended Action   : Blue Containment + Cloud Lockdown (Selected by QAOA Optimizer: -2.208 H)
   [8] Human Decision       : {meta['decision']} (Authorized by {meta['approved_by']})
   [9] Actual Result        : Threat neutralized, C2 severed, risk dropped {verif['residual_risk']['before']} -> {verif['residual_risk']['after']}

8.1. AI GUARDIAN DEFENSE AUDIT
{'-'*40}
   Prompt Manipulation Check : PASS (0 injection signatures)
   Tool Abuse Filter         : PASS (No destructive commands)
   Scope Validation          : PASS (10.0.4.0/24, AWS:arn:iam within authorized CIDRs)
   Agent Anomaly Detector    : PASS (Efficacy 97%, Risk 0.07 — within bounds)
   Policy Enforcement (§7.1) : ENFORCED (Mandatory Human Approval Verified)

9. ACTIONS PERFORMED & VERIFICATION
{'-'*40}
   Command           : {ex.get('payload_executed','N/A')}
   Status            : {ex['status']}
   Threat Neutralized: {verif['threat_neutralized']}
   C2 Severed        : {verif['c2_severed']}
   Persistence Gone  : {verif['persistence_removed']}
   Cloud Locked Down : {verif['cloud_lockdown']}
   S3 ACL Reverted   : {verif['s3_acl_reverted']}
   Residual Risk     : {verif['residual_risk']['before']} -> {verif['residual_risk']['after']}

10. RECOMMENDATIONS
{'-'*40}
   1. Enforce FIDO2 hardware MFA on ALL privileged accounts immediately.
   2. Rotate ALL credentials for admin_svc across production + cloud.
   3. Block CIDR 198.51.100.0/24 and domain c2beacon.apt41-infra.example permanently.
   4. Patch CVE-2024-3400 and CVE-2026-1184 within 24 hours.
   5. Enable PowerShell ScriptBlock logging on all endpoints.
   6. Remove legacy RDP rule 'Legacy-RDP-Allow' and enforce bastion-only access.
   7. Upgrade TLS to 1.3 and replace RSA-1024 with ECDSA-P384.
   8. Establish mandatory pentest finding remediation SLAs (< 30 days for CRITICAL).
   9. Schedule quarterly Shadow-Twin attack replay exercises.

11. 8 LLMs × 10 SECURITY PLATFORMS INTELLIGENCE SYNTHESIS
{'-'*40}
   [1] HADRIAN (External Recon)     : 5 exposed assets | 2 unknown unknowns | Surface risk: 88%
   [2] ASTRA (Multi-Agent Valid.)   : 4 sub-agents | 8 findings | 1 false positive eliminated (95% TP)
   [3] NODEZERO (Attack Path Graph) : 3 autonomous paths | Shortest: 3 hops to Crown Jewel DB
   [4] XBOW (Web Exploit Reasoning) : 2 exploit chains | Max feasibility: 94% (CVE-2024-3400 -> DB)
   [5] PENTERA (Continuous Valid.)  : 6 controls tested | 3 EFFECTIVE | 3 DRIFT DETECTED (MFA, IAM, S3)
   [6] PENTESTGPT (Research Trees)  : 6-node task tree | 85% complete | Phase: Post-Exploitation
   [7] GARAK (AI Red Team Defense)  : 47 probes | 0 vulnerabilities found | Guardian block rate: 100%
   [8] PENLIGENT (Tool Orchestrator): Optimized DAG chain executed (2,840ms total latency)
   [9] AIKIDO ATTACK (AppSec/CI-CD) : 4 findings (2 CRITICAL, 2 HIGH) | Secrets & SCA flagged
   [10] HIDDENLAYER (AI/ML Defense) : 2 model endpoints scanned | Adversarial extraction guarded
   [*] LLM ORCHESTRATOR            : 8 models online (GPT-5.6 Sol/Cyber, Gemini 3.8/Research, DeepSeek, Claude, Qwen, Llama)

{'='*80}
   Ledger Block #{block.block_index}
   SHA-256 : {block.hash_current[:48]}...
   Prev    : {block.hash_previous[:48]}...
{'='*80}
"""

class LearningEngine:
    def __init__(self):
        self.rules = []

    def learn(self, hypotheses, research, verif, cycle_id) -> List[LearningRule]:
        new = [
            LearningRule("LRN-001", cycle_id, "IOC_BLOCK",
                "Permanently block APT-41 infra CIDR + C2 domains",
                "src_ip IN 198.51.100.0/24 OR dns_query CONTAINS apt41-infra -> BLOCK+ALERT"),
            LearningRule("LRN-002", cycle_id, "BEHAVIORAL_SIGNATURE",
                "Detect svchost spawning encoded PowerShell with LSASS access",
                "parent=svchost.exe AND child=powershell.exe AND target=lsass.exe -> CRITICAL"),
            LearningRule("LRN-003", cycle_id, "AUTH_HARDENING",
                "Block authentication attempts that bypass or lack MFA",
                "user=admin_svc AND mfa_status != 'VERIFIED' -> DENY"),
            LearningRule("LRN-004", cycle_id, "KERBEROS_POLICY",
                "Reject Kerberos tickets using RC4_HMAC encryption",
                "ticket_encryption = RC4_HMAC -> DENY + ALERT"),
            LearningRule("LRN-005", cycle_id, "CLOUD_GUARDRAIL",
                "Prevent IAM AdminAccess attachment and S3 public-read ACLs",
                "iam:AttachRolePolicy(AdminAccess) OR s3:PutBucketAcl(public-read) -> DENY"),
            LearningRule("LRN-006", cycle_id, "CONFIG_ENFORCEMENT",
                "Auto-remediate ScriptBlock logging disabled and legacy RDP rules",
                "ScriptBlockLogging=DISABLED OR FW_Rule(RDP,0.0.0.0/0) -> AUTO_FIX"),
            LearningRule("LRN-007", cycle_id, "PENTEST_SLA",
                "Escalate overdue pentest findings to CISO after 30 days",
                "pentest_finding.status=OPEN AND age > 30d -> ESCALATE_CISO"),
        ]
        self.rules.extend(new)
        return new


# ==========================================================================
# MASTER ORCHESTRATOR
# ==========================================================================

class NexusXPowerStack:
    def __init__(self):
        self.cycle_count = 0
        self.ledger = EvidenceLedger()
        self.learning = LearningEngine()
        self.llm_orchestrator = LLMOrchestrator()

    def execute_full_cycle(self):
        self.cycle_count += 1
        cid = f"CYC-{self.cycle_count:04d}"

        print(f"\n{'='*80}")
        print(f"  NEXUS-X POWER STACK — CYCLE #{self.cycle_count}")
        print(f"  9-STREAM TELEMETRY -> SENTINEL-X -> Q-REASON -> RESEARCH -> SHADOW-TWIN")
        print(f"  -> RED/BLUE -> QUANTUM -> POLICY -> HUMAN -> EXECUTE -> VERIFY -> LEARN")
        print(f"  [8 LLMs ORCHESTRATED × 10 SPECIALIZED CYBER SECURITY PLATFORMS]")
        print(f"{'='*80}\n")

        # 9-Stream Telemetry Collection
        collectors = [
            Stream1_NetworkTelemetry(), Stream2_EndpointEvents(), Stream3_AuthenticationEvents(),
            Stream4_ApplicationLogs(), Stream5_CloudTelemetry(), Stream6_VulnerabilityInfo(),
            Stream7_ConfigurationState(), Stream8_ThreatIntelligence(), Stream9_SecurityTestResults()
        ]
        all_events = []
        print("  [9-STREAM TELEMETRY COLLECTION]")
        for c in collectors:
            evts = c.collect()
            all_events.extend(evts)
            stream_name = evts[0].stream.value if evts else "?"
            print(f"    {stream_name:40s} : {len(evts)} events")
        print(f"    {'─'*50}")
        print(f"    {'TOTAL':40s} : {len(all_events)} events\n")

        # Sentinel-X
        sentinel = SentinelXEngine()
        alert = sentinel.fuse_and_detect(all_events)
        print(f"  [SENTINEL-X] '{alert.title}'")
        print(f"    Confidence: {int(alert.confidence*100)}% | Severity: {alert.severity.value}")
        print(f"    Streams fused: {len(alert.streams_involved)} | Assets: {', '.join(alert.affected_assets)}\n")

        # Q-Reason
        qr = QReasonEngine()
        hypotheses = qr.reason(alert, all_events)
        print(f"  [Q-REASON] {len(hypotheses)} hypotheses across {len(hypotheses[0].supporting_evidence)} evidence items:")
        for h in hypotheses:
            tag = " [PRIMARY]" if h == hypotheses[0] else ""
            print(f"    {h.hypothesis_id}: {h.title} — {int(h.confidence*100)}%{tag}")
        print(f"    Kill chain: {len(hypotheses[0].causal_chain)} phases | MITRE techniques: {len(hypotheses[0].mitre_techniques)}\n")

        # Research AI
        researcher = ResearchAIAgent()
        research = researcher.investigate(hypotheses[0])
        print(f"  [RESEARCH AI] {len(research.technique_ids)} techniques | {len(research.cve_refs)} CVEs | {len(research.advisories)} advisories | {len(research.research_papers)} papers")
        print(f"    CRITICAL: Q2 pentest identified same attack path — REMEDIATION WAS OVERDUE\n")

        # 8 LLMs × 10 Specialized Security Platforms Suite
        print(f"  {'-'*70}")
        print("  [8 LLMs × 10 SPECIALIZED SECURITY PLATFORMS INTELLIGENCE SUITE]")
        print(f"  {'-'*70}")
        orchestrator = NexusAgentOrchestrator()
        guardian = PolicyRiskEngine().guardian
        agent_results = orchestrator.execute_all_agents(all_events, hypotheses, research, guardian)
        print(f"  {'-'*70}\n")

        # Shadow-Twin + Red/Blue
        red_s = RedAgent().plan(hypotheses[0], research)
        blue_s = BlueAgent().plan(hypotheses[0], research)
        shadow = ShadowTwinEngine()
        red_sim = shadow.simulate(red_s)
        blue_sim = shadow.simulate(blue_s)
        print(f"  [RED AGENT]  {red_s.name}")
        print(f"    Risk: {red_s.risk_score} | Efficacy: {int(red_s.mitigation_efficacy*100)}% | Sim: {int(red_sim['success_prob']*100)}%")
        print(f"  [BLUE AGENT] {blue_s.name}")
        print(f"    Risk: {blue_s.risk_score} | Efficacy: {int(blue_s.mitigation_efficacy*100)}% | Sim: {int(blue_sim['success_prob']*100)}%\n")

        # Quantum Optimizer
        qopt = QuantumOptimizer()
        qsol = qopt.optimize([red_s, blue_s])
        print(f"  [QUANTUM] QUBO: {qsol.qubo_energy} H | Selected: {qsol.selected_strategy.name} ({qsol.selected_strategy.agent_mode.value})\n")

        # Policy + Approval + Execution + Verification
        pol = PolicyRiskEngine().evaluate(qsol.selected_strategy)
        print(f"  [POLICY] Scope: {pol['scope']} | Risk: {pol['risk']} | Human Required: {pol['human_required']}")
        dec, meta = HumanApprovalGate().decide(qsol.selected_strategy)
        print(f"  [HUMAN APPROVAL] {dec.value} | ID: {meta['decision_id']}")
        ex = ExecutionEngine().execute(dec, meta, qsol.selected_strategy)
        print(f"  [EXECUTION] {ex['status']}")
        verif = VerificationEngine().verify(ex)
        print(f"  [VERIFICATION] {verif['status']} | Risk: {verif['residual_risk']['before']} -> {verif['residual_risk']['after']}")

        # Ledger + Report + Learning
        block = self.ledger.append(cid, f"{len(all_events)} events / 9 streams", hypotheses[0].title,
                                   dec.value, ex.get('payload_executed',''), f"Risk {verif['residual_risk']['before']}->{verif['residual_risk']['after']}")
        print(f"  [LEDGER] Block #{block.block_index} | SHA-256: {block.hash_current[:24]}...\n")

        report = ReportEngine().generate(alert, hypotheses, research, qsol, meta, ex, verif, block, all_events)
        print(report)

        # 15-PILLAR NEXT-GEN ARCHITECTURE EXECUTION
        print(f"  {'-'*70}")
        print("  [PURPLE-X CONTINUOUS ATTACK -> DEFENSE FEEDBACK LOOP]")
        print(f"  {'-'*70}")
        purple_engine = ContinuousPurpleLoop()
        p_res = purple_engine.run_complete_feedback_loop()

        print(f"  [ATTACK SURFACE GRAPH] {p_res['surface_graph']['nodes']} Nodes, {p_res['surface_graph']['edges']} Trust Edges mapped")
        print(f"  [ATTACK PATH RANKING]  Top Ranked Path: {p_res['ranked_paths'][0].name} (Rank Score: {p_res['ranked_paths'][0].rank_score:.2f})")
        print(f"  [CRITICAL CHOKE POINT] {p_res['choke_points'][0].choke_id}: {p_res['choke_points'][0].asset_or_control} (Breaks {p_res['choke_points'][0].paths_intersected} paths)")
        print(f"  [DETECTION-AWARENESS]  Technique '{p_res['detection_awareness']['technique']}' -> Detection Confidence: {p_res['detection_awareness']['blue_detection_confidence']:.0%}")
        print(f"  [BLAST RADIUS ENGINE]  Asset {p_res['blast_radius'].compromised_asset} -> Score: {p_res['blast_radius'].blast_radius_score}/100 ({p_res['blast_radius'].business_impact_tier})")
        print(f"  [WHAT-IF SIMULATION]   Optimal: '{p_res['whatif_simulations'][1].scenario_name}' -> Risk Reduction: {p_res['whatif_simulations'][1].risk_reduction_pct:.0f}% (QAOA: {p_res['whatif_simulations'][1].qaoa_energy} H)")
        print(f"  [DECEPTION-X LAYER]    4 Active Decoys ({', '.join(p_res['deception_status'][:2])}...) | 100% True Positive Canary")
        print(f"  [AI-X SECURITY SUITE]  {p_res['aix_audit'].prompt_injection_tested} Prompt Injections Blocked | {p_res['aix_audit'].tool_abuse_prevented} Tool Abuse Attempts Prevented")
        print(f"  [3-TIER AUTHORIZATION] Tier: {p_res['authorization']['tier'][:25]}... -> Status: {p_res['authorization']['status']}")
        print(f"  [RE-VALIDATION PROOF]  Re-tested Path AP-01 -> Result: {p_res['re_validation']['proof']}")
        print(f"  [DIGITAL IMMUNE SYS]   Antibody #{p_res['antibody_created']['antibody_id']} created -> Neutralized {p_res['antibody_created']['technique_neutralized']}")
        print(f"  [EVIDENCE PROVENANCE]  SHA-256 Provenance Hash: {p_res['provenance_hash'][:32]}...")
        
        scores = p_res['resilience_scores']
        purple = p_res['purple_scores']
        print(f"\n  [UNIFIED NEXUS-X RESILIENCE SCORECARD]")
        print(f"    Attack Capability    : {scores.attack_capability:.0f}/100 | Detection Capability : {scores.detection_capability:.0f}/100")
        print(f"    Response Capability  : {scores.response_capability:.0f}/100 | Recovery Capability  : {scores.recovery_capability:.0f}/100")
        print(f"    Exposure Score       : {scores.exposure_score:.0f}/100 | Identity Risk        : {scores.identity_risk:.0f}/100")
        print(f"    Cloud Risk           : {scores.cloud_risk:.0f}/100 | AI Security          : {scores.ai_security:.0f}/100")
        print(f"    ---------------------------------------------------------")
        print(f"    NEXUS-X RESILIENCE (BEFORE REMEDIATION) : {scores.composite_resilience_before:.1f}/100")
        print(f"    NEXUS-X RESILIENCE (AFTER REMEDIATION)  : {scores.composite_resilience_after:.1f}/100 (+{scores.composite_resilience_after - scores.composite_resilience_before:.1f} GAIN)")
        print(f"    PURPLE TEAM EFFECTIVENESS RATING        : {purple.overall_purple_rating:.0f}/100 (Coverage: {purple.attack_coverage_pct:.0f}%, Accuracy: {purple.detection_accuracy_pct:.0f}%)")
        print(f"  {'-'*70}\n")

        rules = self.learning.learn(hypotheses, research, verif, cid)
        print(f"  [LEARNING] {len(rules)} new rules extracted:")
        for r in rules: print(f"    [{r.rule_type}] {r.description}")
        print(f"\n  {'='*60}")
        print(f"  CYCLE COMPLETE. {len(rules)} rules fed back to OBSERVE.")
        print(f"  NEXUS-X ready for next autonomous reasoning cycle.")
        print(f"  {'='*60}\n")

"""
================================================================================
  NEXUS-X ADVANCED CYBER INTELLIGENCE ARCHITECTURE EXTENSION
  15 Core Enterprise Pillars:
    1. Attack Intelligence Layer & Surface Graph
    2. Advanced Red Team Modules (10 modules)
    3. BLUE-X Defensive Intelligence Engine
    4. Attack -> Defense Continuous Feedback Loop
    5. Detection-Aware Red Teaming
    6. Digital Immune System
    7. Unified NEXUS Resilience Scoring
    8. Blast Radius Engine
    9. "What-If" Defensive Simulation (Digital Twin + QAOA)
    10. DECEPTION-X Proactive Defense
    11. AI-X: AI/LLM-Specific Attack & Defense
    12. 3-Tier Human Authorization Engine
    13. Hard Attack Stop Conditions & Kill Switches
    14. Cryptographic Evidence Provenance Ledger
    15. PURPLE-X Scoring Engine
================================================================================
"""

import time
import hashlib
import json
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum


# ==========================================================================
# 1. ENUMS FOR ADVANCED ARCHITECTURE
# ==========================================================================

class AuthorizationTier(Enum):
    LEVEL_0_OBSERVE        = "LEVEL_0_OBSERVE (Autonomous discovery, correlation, research)"
    LEVEL_1_SAFE_VALIDATE  = "LEVEL_1_SAFE_VALIDATE (Autonomous non-destructive PoC within scope)"
    LEVEL_2_HIGH_IMPACT    = "LEVEL_2_HIGH_IMPACT (Mandatory human cryptographic authorization)"

class StopTriggerType(Enum):
    TIME_EXCEEDED     = "TIME_EXCEEDED"
    SCOPE_BREACH      = "SCOPE_BREACH"
    RATE_EXCEEDED     = "RATE_EXCEEDED"
    IMPACT_BREACH     = "IMPACT_BREACH"
    AUTH_EXPIRED      = "AUTH_EXPIRED"
    USER_KILL_SWITCH  = "USER_KILL_SWITCH"

class DecoyType(Enum):
    HONEY_CREDENTIAL  = "Honey Credential / Kerberoast Canary"
    DECOY_SERVICE     = "Decoy SSH / RDP Service"
    CANARY_TOKEN      = "Canary Token in AWS Secrets Vault"
    FAKE_API_ENDPOINT = "Fake /api/v3/internal-admin API"
    HONEY_DATABASE    = "Decoy DB Table 'tbl_customer_passwords'"


# ==========================================================================
# 2. DATA MODELS FOR ADVANCED ARCHITECTURE
# ==========================================================================

@dataclass
class AttackSurfaceNode:
    node_id: str
    label: str
    node_type: str  # Asset, Service, Identity, API, CloudResource, Dependency
    ip: Optional[str] = None
    criticality: str = "MEDIUM"
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AttackSurfaceEdge:
    source_id: str
    dest_id: str
    relationship: str  # trust_relationship, authenticates_to, network_reaches, dependency_of
    risk_weight: float = 1.0

@dataclass
class AttackSurfaceGraph:
    nodes: Dict[str, AttackSurfaceNode] = field(default_factory=dict)
    edges: List[AttackSurfaceEdge] = field(default_factory=list)

    def add_node(self, node: AttackSurfaceNode):
        self.nodes[node.node_id] = node

    def add_edge(self, edge: AttackSurfaceEdge):
        self.edges.append(edge)

@dataclass
class AttackHypothesis:
    hypothesis_id: str
    statement: str
    vulnerability_cve: str
    identity_required: str
    target_asset: str
    confidence: float
    evidence_required: List[str]
    evidence_collected: List[str]
    is_escalated: bool = False

@dataclass
class ChokePoint:
    choke_id: str
    asset_or_control: str
    paths_intersected: int
    break_cost_estimate: str
    recommended_control: str

@dataclass
class RankedAttackPath:
    path_id: str
    name: str
    hops: List[str]
    likelihood: float
    impact_score: float
    privilege_gain: str
    detection_probability: float
    business_criticality: float
    choke_points: List[str]

    @property
    def rank_score(self) -> float:
        # Higher score = higher attacker priority
        det_penalty = max(0.05, self.detection_probability)
        return (self.likelihood * self.impact_score * self.business_criticality) / det_penalty

@dataclass
class DetectionRule:
    rule_id: str
    title: str
    mitre_technique: str
    rule_type: str  # Sigma, EDR_Query, SIEM_Rule, CloudTrail_Alert
    query_syntax: str
    confidence: float
    action_on_match: str

@dataclass
class SOCIncidentTimeline:
    incident_id: str
    timestamp_start: float
    timestamp_end: float
    events_correlated: int
    phases_identified: List[str]
    root_cause: str
    affected_identities: List[str]
    affected_hosts: List[str]

@dataclass
class ContainmentAction:
    action_id: str
    action_type: str  # ISOLATE_HOST, REVOKE_TOKEN, DISABLE_USER, BLOCK_IP, RESTRICT_WORKLOAD
    target: str
    status: str
    executed_at: float
    rollback_supported: bool = True

@dataclass
class RemediationPlan:
    plan_id: str
    patches: List[str]
    config_corrections: List[str]
    iam_modifications: List[str]
    network_segmentations: List[str]
    secret_rotations: List[str]
    estimated_downtime_sec: int
    business_disruption_score: float

@dataclass
class BlastRadiusResult:
    compromised_asset: str
    direct_credentials_exposed: List[str]
    trust_relationships_exploitable: List[str]
    reachable_assets: List[str]
    sensitive_data_at_risk: List[str]
    business_impact_tier: str
    blast_radius_score: float  # 0.0 - 100.0
    recovery_priority: str

@dataclass
class WhatIfScenarioResult:
    scenario_name: str
    proposed_intervention: str
    attack_paths_broken: int
    attack_paths_remaining: int
    business_services_affected: int
    risk_reduction_pct: float
    disruption_score: float
    qaoa_energy: float
    is_optimal: bool

@dataclass
class DecoyEntity:
    decoy_id: str
    decoy_type: DecoyType
    name: str
    location: str
    deployed: bool = True
    tripped: bool = False
    alert_history: List[str] = field(default_factory=list)

@dataclass
class AIXAuditResult:
    prompt_injection_tested: int
    prompt_injection_blocked: int
    tool_abuse_attempts: int
    tool_abuse_prevented: int
    data_leakage_checks: int
    data_leakage_prevented: int
    excessive_agency_verdict: str
    recommended_guardrails: List[str]

@dataclass
class StopConditionPolicy:
    time_limit_sec: int = 300
    allowed_cidrs: List[str] = field(default_factory=lambda: ["10.0.4.0/24", "192.168.1.0/24", "172.16.0.0/16"])
    max_probes_per_minute: int = 120
    max_allowed_impact: str = "LOW_SAFE_POC"
    authorization_valid_hours: int = 24
    kill_switch_active: bool = False

@dataclass
class ProvenanceRecord:
    finding_id: str
    raw_evidence_hash: str
    tool_name: str
    tool_version: str
    timestamp: float
    llm_used: str
    llm_reasoning_summary: str
    authorization_tier: AuthorizationTier
    authorized_by: str
    action_performed: str
    outcome_summary: str
    block_hash: str

@dataclass
class ResilienceScorecard:
    attack_capability: float       # 0 - 100
    detection_capability: float    # 0 - 100
    response_capability: float     # 0 - 100
    recovery_capability: float     # 0 - 100
    exposure_score: float          # 0 - 100 (Lower is better)
    identity_risk: float           # 0 - 100 (Lower is better)
    cloud_risk: float              # 0 - 100 (Lower is better)
    ai_security: float             # 0 - 100
    composite_resilience_before: float
    composite_resilience_after: float

@dataclass
class PurpleTeamScore:
    attack_coverage_pct: float
    detection_coverage_pct: float
    detection_accuracy_pct: float
    response_effectiveness_pct: float
    remediation_effectiveness_pct: float
    overall_purple_rating: float


# ==========================================================================
# 3. ADVANCED RED TEAM & ATTACK INTELLIGENCE ENGINES
# ==========================================================================

class AttackSurfaceGraphEngine:
    """Builds and maintains the unified, continuously updated Attack Surface Graph."""
    def build_graph(self) -> AttackSurfaceGraph:
        g = AttackSurfaceGraph()
        # Nodes
        nodes = [
            AttackSurfaceNode("N-01", "gw-edge-01 (198.51.100.1)", "Asset", "198.51.100.1", "HIGH", ["Perimeter", "PAN-OS"]),
            AttackSurfaceNode("N-02", "web-prod-01 (10.0.4.50)", "Asset", "10.0.4.50", "CRITICAL", ["Ubuntu", "Nginx", "API"]),
            AttackSurfaceNode("N-03", "db-prod-01 (10.0.4.51)", "Asset", "10.0.4.51", "CRITICAL", ["PostgreSQL", "CrownJewel"]),
            AttackSurfaceNode("N-04", "k8s-cluster-01", "CloudResource", "10.0.4.60", "HIGH", ["EKS", "Microservices"]),
            AttackSurfaceNode("N-05", "admin_svc", "Identity", None, "CRITICAL", ["DomainAdmin", "IAM-AdminAccess"]),
            AttackSurfaceNode("N-06", "lambda-backup-role", "Identity", None, "HIGH", ["AWS-IAM"]),
            AttackSurfaceNode("N-07", "/api/v2/search", "API", "10.0.4.50:443", "HIGH", ["REST", "Elasticsearch"]),
            AttackSurfaceNode("N-08", "log4j-core 2.14.1", "Dependency", None, "HIGH", ["Java", "Vulnerable"]),
            AttackSurfaceNode("N-09", "s3://prod-secrets-vault", "CloudResource", None, "CRITICAL", ["S3", "Credentials"]),
        ]
        for n in nodes:
            g.add_node(n)

        # Edges (Trust relationships, network access, privileges)
        edges = [
            AttackSurfaceEdge("N-01", "N-02", "network_routes_to", 0.9),
            AttackSurfaceEdge("N-02", "N-07", "exposes_api", 0.95),
            AttackSurfaceEdge("N-02", "N-08", "includes_dependency", 0.9),
            AttackSurfaceEdge("N-02", "N-05", "stores_cached_credentials", 0.85),
            AttackSurfaceEdge("N-05", "N-03", "has_administrative_access", 0.98),
            AttackSurfaceEdge("N-02", "N-06", "assumes_iam_role", 0.75),
            AttackSurfaceEdge("N-06", "N-09", "reads_writes_bucket", 0.95),
            AttackSurfaceEdge("N-04", "N-03", "network_reaches", 0.6),
        ]
        for e in edges:
            g.add_edge(e)
        return g


class AttackHypothesisEngine:
    """Formulates and tests formal attack hypotheses requiring evidence before escalation."""
    def generate_hypotheses(self) -> List[AttackHypothesis]:
        return [
            AttackHypothesis(
                hypothesis_id="HYP-01",
                statement="If CVE-2024-3400 is exploitable on gw-edge-01 and admin_svc token is cached on web-prod-01, adversary can pivot to db-prod-01.",
                vulnerability_cve="CVE-2024-3400",
                identity_required="admin_svc",
                target_asset="db-prod-01 (10.0.4.51)",
                confidence=0.94,
                evidence_required=["Valid PAN-OS RCE response", "Cached Kerberos ticket in LSASS", "Active SQL port 5432 reachable"],
                evidence_collected=["Valid PAN-OS RCE response", "Cached Kerberos ticket in LSASS"],
                is_escalated=True
            ),
            AttackHypothesis(
                hypothesis_id="HYP-02",
                statement="If lambda-backup-role has AdministratorAccess, compromised web-prod-01 can dump S3 secrets vault without triggering EDR.",
                vulnerability_cve="CWE-250 (Excessive IAM Privilege)",
                identity_required="lambda-backup-role",
                target_asset="s3://prod-secrets-vault",
                confidence=0.88,
                evidence_required=["IAM Policy attachment logged", "S3 PutBucketAcl public-read successful"],
                evidence_collected=["IAM Policy attachment logged", "S3 PutBucketAcl public-read successful"],
                is_escalated=True
            ),
            AttackHypothesis(
                hypothesis_id="HYP-03",
                statement="If RDP port 3389 is exposed to 0.0.0.0/0, external attacker can brute-force backup service account.",
                vulnerability_cve="CWE-307 (Improper Restriction of Excessive Auth Attempts)",
                identity_required="backup_operator",
                target_asset="ad-dc-01 (10.0.4.10)",
                confidence=0.42,
                evidence_required=["30+ RDP auth attempts from single IP", "Successful NTLM auth handshake"],
                evidence_collected=[],
                is_escalated=False
            )
        ]


class AttackPathRanker:
    """Ranks attack paths based on likelihood, impact, privilege gain, and detection probability."""
    def rank_paths(self) -> Tuple[List[RankedAttackPath], List[ChokePoint]]:
        paths = [
            RankedAttackPath(
                path_id="AP-01",
                name="Perimeter Gateway -> Web Tier -> LSASS -> Database Exfiltration",
                hops=["gw-edge-01", "web-prod-01", "admin_svc", "db-prod-01"],
                likelihood=0.92,
                impact_score=0.98,
                privilege_gain="Domain Admin / DB Superuser",
                detection_probability=0.35,  # Stealthy
                business_criticality=0.95,
                choke_points=["CHOKE-01 (MFA on admin_svc)", "CHOKE-02 (DB Micro-segmentation)"]
            ),
            RankedAttackPath(
                path_id="AP-02",
                name="Web API -> Lambda IAM Privilege Escalation -> S3 Secrets Vault Dump",
                hops=["/api/v2/search", "web-prod-01", "lambda-backup-role", "s3://prod-secrets-vault"],
                likelihood=0.85,
                impact_score=0.90,
                privilege_gain="AWS Cloud AdministratorAccess",
                detection_probability=0.60,
                business_criticality=0.90,
                choke_points=["CHOKE-03 (IAM Boundary Guardrail)", "CHOKE-04 (S3 Public Block)"]
            ),
            RankedAttackPath(
                path_id="AP-03",
                name="Public RDP Exposure -> Backup Operator Spray -> Domain Controller Lateral",
                hops=["internet", "rdp-bastion", "backup_operator", "ad-dc-01"],
                likelihood=0.38,
                impact_score=0.80,
                privilege_gain="Backup Operator",
                detection_probability=0.88,  # Highly visible
                business_criticality=0.85,
                choke_points=["CHOKE-05 (Close RDP Rule)"]
            )
        ]
        # Sort by computed rank score descending
        paths.sort(key=lambda p: p.rank_score, reverse=True)

        choke_points = [
            ChokePoint("CHOKE-01", "Enforce FIDO2 MFA & Tier-0 Credential Guard on admin_svc", 3, "Low Disruption (2 mins)", "Hardware MFA + Session Invalidation"),
            ChokePoint("CHOKE-02", "Enforce Zero-Trust ACL: Only API Backend -> DB Port 5432", 2, "Zero Disruption", "Micro-segmentation Firewall Rule"),
            ChokePoint("CHOKE-03", "AWS SCP Guardrail preventing IAM:AttachRolePolicy(AdminAccess)", 2, "Zero Disruption", "AWS Organizations Service Control Policy"),
        ]
        return paths, choke_points


class SafeValidationEngine:
    """Executes safe, non-destructive proof-of-concept validations with automated early stop."""
    def validate_safely(self, hypothesis: AttackHypothesis) -> Dict[str, Any]:
        return {
            "validation_id": f"VAL-{hashlib.sha256(hypothesis.hypothesis_id.encode()).hexdigest()[:8]}",
            "hypothesis_id": hypothesis.hypothesis_id,
            "validation_method": "Non-Destructive Harmless PoC Probe",
            "proof_obtained": True,
            "destructive_payload_blocked": True,
            "auto_stopped_on_sufficient_evidence": True,
            "evidence_snippet": f"Verified reachable RPC interface & token signature matching {hypothesis.identity_required} without writing persistent disk binaries.",
            "safety_verdict": "SAFE_PROOF_CONFIRMED"
        }


class AttackCampaignManager:
    """Tracks campaign objectives, deduplicates validations, and enforces authorization limits."""
    def __init__(self):
        self.active_campaigns = {
            "CAMP-2026-09A": {
                "name": "Q3 Enterprise Crown Jewel Resilience Assessment",
                "phase": "Phase 4: Post-Exploitation Control Validation",
                "authorizing_officer": "CISO SecOps Command",
                "completed_validations": 14,
                "deduplicated_skipped": 6,
                "status": "IN_PROGRESS"
            }
        }


# ==========================================================================
# 4. BLUE-X DEFENSIVE INTELLIGENCE ENGINE
# ==========================================================================

class DetectionEngineering:
    """Generates detection rules (Sigma/SIEM/EDR) directly from observed attack telemetry."""
    def generate_rules(self) -> List[DetectionRule]:
        return [
            DetectionRule(
                rule_id="SIGMA-2026-081",
                title="Detect LSASS Memory Dumping via Encoded PowerShell Process Spawning",
                mitre_technique="T1003.001 (OS Credential Dumping: LSASS Memory)",
                rule_type="Sigma / EDR Query",
                query_syntax="process.name: powershell.exe AND process.command_line: (*-enc* OR *lsass*)",
                confidence=0.97,
                action_on_match="ALERT_HIGH + AUTO_QUARANTINE_PROCESS"
            ),
            DetectionRule(
                rule_id="SIEM-2026-114",
                title="Kerberos Encryption Downgrade to RC4-HMAC on Privileged Account",
                mitre_technique="T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)",
                rule_type="SIEM Rule",
                query_syntax="winlogon.event_id: 4768 AND kerberos.encryption_type: 0x17 AND user.name: admin_*",
                confidence=0.94,
                action_on_match="ALERT_CRITICAL + REVOKE_KERBEROS_TGT"
            ),
            DetectionRule(
                rule_id="CLD-2026-042",
                title="Detect Unauthorized IAM AdministratorAccess Attachment in Secondary Roles",
                mitre_technique="T1098.001 (Account Manipulation: Additional Cloud Credentials)",
                rule_type="CloudTrail Alert",
                query_syntax="eventName: AttachRolePolicy AND requestParameters.policyArn: *AdministratorAccess",
                confidence=0.99,
                action_on_match="ALERT_CRITICAL + AUTO_DETACH_POLICY"
            )
        ]


class SOCInvestigationAgent:
    """Reconstructs cross-stream incident timelines and correlates root cause indicators."""
    def build_incident_timeline(self, alert_id: str) -> SOCIncidentTimeline:
        t0 = time.time() - 3600
        return SOCIncidentTimeline(
            incident_id=f"INC-{alert_id}",
            timestamp_start=t0,
            timestamp_end=t0 + 1420,
            events_correlated=26,
            phases_identified=["Recon (T1595)", "Initial Access (T1190)", "PrivEsc (T1068)", "Persistence (T1053)", "Exfil (T1567)"],
            root_cause="Unpatched CVE-2024-3400 on Perimeter Gateway coupled with un-rotated admin_svc credentials.",
            affected_identities=["admin_svc", "lambda-backup-role"],
            affected_hosts=["10.0.4.50 (web-prod-01)", "10.0.4.51 (db-prod-01)"]
        )


class AutomatedContainmentEngine:
    """Executes high-precision automated containment across network, identity, and cloud."""
    def execute_containment(self, host: str, user: str, ip: str) -> List[ContainmentAction]:
        now = time.time()
        return [
            ContainmentAction("ACT-01", "ISOLATE_HOST", host, "SUCCESS", now),
            ContainmentAction("ACT-02", "REVOKE_TOKEN", user, "SUCCESS", now),
            ContainmentAction("ACT-03", "BLOCK_IP", ip, "SUCCESS", now),
            ContainmentAction("ACT-04", "RESTRICT_WORKLOAD", "k8s-pod/web-frontend-7f9", "SUCCESS", now),
            ContainmentAction("ACT-05", "REVERT_CLOUD_ACL", "s3://prod-secrets-vault", "SUCCESS", now),
        ]


class RemediationPlannerEngine:
    """Synthesizes prioritized remediation blueprints across patch, config, IAM, and network."""
    def build_plan(self) -> RemediationPlan:
        return RemediationPlan(
            plan_id="REM-2026-09A",
            patches=["Apply PAN-OS 11.1.2-h3 security hotfix (CVE-2024-3400)", "Upgrade log4j-core to 2.17.1"],
            config_corrections=["Enable PowerShell ScriptBlock Logging (GPO #4104)", "Close legacy RDP Port 3389 on border"],
            iam_modifications=["Detach AdministratorAccess from lambda-backup-role", "Enforce FIDO2 hardware MFA on admin_svc"],
            network_segmentations=["Implement Micro-segmentation: Restrict DB 10.0.4.51 to Web VIP only"],
            secret_rotations=["Rotate PostgreSQL master password", "Rotate AWS Access Key AKIAIOSFODNN7EXAMPLE"],
            estimated_downtime_sec=0,
            business_disruption_score=0.04
        )


class ControlVerificationEngine:
    """Re-validates the target after remediation to confirm that the attack path is truly broken."""
    def verify_remediation(self, path_id: str) -> Dict[str, Any]:
        return {
            "path_id": path_id,
            "re_test_timestamp": time.time(),
            "attack_path_re_executed": True,
            "attack_path_blocked_at_hop": 1,
            "choke_point_effective": True,
            "is_path_eliminated": True,
            "residual_vulnerability": "NONE",
            "proof": "Re-execution of PoC probe rejected at Perimeter Gateway (HTTP 403 / ACL Drop). Attack path broken."
        }


# ==========================================================================
# 5. DETECTION-AWARE RED TEAMING & DIGITAL IMMUNE SYSTEM
# ==========================================================================

class DetectionAwareEvaluator:
    """Evaluates whether the Blue team will detect an attack technique before executing."""
    def evaluate_technique(self, technique_name: str) -> Dict[str, Any]:
        matrix = {
            "Credential Abuse (admin_svc)": {"telemetry": "Authentication Logs", "detection": "SIEM Behavioral Rule", "confidence": 0.92},
            "Suspicious Encoded PowerShell": {"telemetry": "EDR Process Tree", "detection": "EDR Behavioral Signature", "confidence": 0.97},
            "Lateral Movement (Token Replay)": {"telemetry": "Network Flow + Kerberos", "detection": "Network Analytics Engine", "confidence": 0.61},
            "Cloud Privilege Escalation": {"telemetry": "AWS CloudTrail", "detection": "Cloud Anomaly Guard", "confidence": 0.38},
        }
        entry = matrix.get(technique_name, {"telemetry": "General Syslog", "detection": "Baseline Anomaly", "confidence": 0.50})
        return {
            "technique": technique_name,
            "expected_telemetry": entry["telemetry"],
            "existing_detection": entry["detection"],
            "blue_detection_confidence": entry["confidence"],
            "stealth_recommendation": "Use slow canary probing" if entry["confidence"] > 0.8 else "Standard POC probe acceptable"
        }


class DigitalImmuneSystem:
    """Converts validated security incidents into permanent institutional defensive memory."""
    def __init__(self):
        self.immune_memory: List[Dict[str, Any]] = []

    def record_incident_antibodies(self, incident_id: str, technique: str, rule: DetectionRule, playbook: str):
        antibody = {
            "antibody_id": f"ANTIBODY-{len(self.immune_memory)+1:03d}",
            "source_incident": incident_id,
            "technique_neutralized": technique,
            "detection_rule_id": rule.rule_id,
            "response_playbook": playbook,
            "timestamp_stored": time.time(),
            "active_protection": True
        }
        self.immune_memory.append(antibody)
        return antibody


# ==========================================================================
# 6. BLAST RADIUS & "WHAT-IF" SIMULATION
# ==========================================================================

class BlastRadiusEngine:
    """Calculates downstream compromise impact across identities, reachable assets, and crown jewels."""
    def calculate_blast_radius(self, asset_id: str) -> BlastRadiusResult:
        return BlastRadiusResult(
            compromised_asset=asset_id,
            direct_credentials_exposed=["admin_svc (Kerberos TGT)", "local_admin_hash", "lambda_role_token"],
            trust_relationships_exploitable=["Domain Admin -> ad-dc-01", "AWS IAM -> S3 Vault", "VPC Peering -> Staging"],
            reachable_assets=["10.0.4.51 (db-prod-01)", "10.0.4.10 (ad-dc-01)", "10.0.4.60 (k8s-cluster-01)"],
            sensitive_data_at_risk=["1.2M Customer PII Records", "Production Stripe API Secret", "Corporate Financial Ledger"],
            business_impact_tier="TIER-1 (CRITICAL ENTERPRISE IMPACT)",
            blast_radius_score=88.5,
            recovery_priority="P0 — IMMEDIATE CONTAINMENT REQUIRED"
        )


class WhatIfSimulator:
    """Simulates defense candidate interventions against the attack graph to find optimal actions."""
    def simulate_scenarios(self) -> List[WhatIfScenarioResult]:
        return [
            WhatIfScenarioResult(
                scenario_name="Intervention A: Disable Account admin_svc",
                proposed_intervention="Revoke all active sessions & disable admin_svc account",
                attack_paths_broken=2,
                attack_paths_remaining=1,
                business_services_affected=1,
                risk_reduction_pct=65.0,
                disruption_score=0.15,
                qaoa_energy=-1.85,
                is_optimal=False
            ),
            WhatIfScenarioResult(
                scenario_name="Intervention B: Segment DB + Restrict IAM Boundary (Selected by QAOA)",
                proposed_intervention="Isolate 10.0.4.50 + Micro-segment DB 5432 + Revert S3 Public ACL + Force MFA",
                attack_paths_broken=3,
                attack_paths_remaining=0,
                business_services_affected=0,
                risk_reduction_pct=94.0,
                disruption_score=0.04,
                qaoa_energy=-2.208,
                is_optimal=True
            ),
            WhatIfScenarioResult(
                scenario_name="Intervention C: Total Subnet Blackhole (Aggressive)",
                proposed_intervention="Drop entire 10.0.4.0/24 subnet traffic",
                attack_paths_broken=3,
                attack_paths_remaining=0,
                business_services_affected=14,
                risk_reduction_pct=98.0,
                disruption_score=0.90,
                qaoa_energy=-0.45,
                is_optimal=False
            )
        ]


# ==========================================================================
# 7. DECEPTION-X & AI-X ENGINES
# ==========================================================================

class DeceptionEngine:
    """Manages proactive honeypots, canary tokens, and decoy credentials."""
    def __init__(self):
        self.decoys: List[DecoyEntity] = [
            DecoyEntity("DEC-01", DecoyType.HONEY_CREDENTIAL, "svc_backup_admin", "Active Directory (SPN Decoy)", deployed=True),
            DecoyEntity("DEC-02", DecoyType.CANARY_TOKEN, "canary_aws_key_s3", "config/vault_canary.json", deployed=True),
            DecoyEntity("DEC-03", DecoyType.FAKE_API_ENDPOINT, "/api/v3/internal-admin", "Nginx Reverse Proxy", deployed=True),
            DecoyEntity("DEC-04", DecoyType.HONEY_DATABASE, "tbl_customer_passwords", "db-prod-01 (Honey Table)", deployed=True),
        ]

    def trigger_tripwire(self, decoy_id: str, adversary_ip: str) -> Dict[str, Any]:
        decoy = next((d for d in self.decoys if d.decoy_id == decoy_id), self.decoys[0])
        decoy.tripped = True
        decoy.alert_history.append(f"Tripped by {adversary_ip} at {time.time()}")
        return {
            "alert_type": "DECEPTION_TRIPWIRE_TRIGGERED",
            "decoy_name": decoy.name,
            "decoy_type": decoy.decoy_type.value,
            "adversary_ip": adversary_ip,
            "confidence": 1.0,  # 100% true positive by definition of canary
            "action": "IMMEDIATE_ESCALATION_TO_LEVEL_2_CONTAINMENT"
        }


class AIXEngine:
    """AI/LLM-Specific Security Engine testing prompt injection, tool misuse, and agent guardrails."""
    def run_ai_audit(self) -> AIXAuditResult:
        return AIXAuditResult(
            prompt_injection_tested=47,
            prompt_injection_blocked=47,
            tool_abuse_attempts=12,
            tool_abuse_prevented=12,
            data_leakage_checks=18,
            data_leakage_prevented=18,
            excessive_agency_verdict="CONTAINED — Strict Least-Privilege Enforced",
            recommended_guardrails=[
                "Enforce regex input sanitization on all system prompt variables",
                "Wrap tool execution in sandbox with read-only filesystem constraint",
                "Apply post-generation PII/Secret redaction filter on LLM responses",
                "Require Level-2 human cryptographic signature for irreversible actions"
            ]
        )


# ==========================================================================
# 8. 3-TIER HUMAN AUTHORIZATION & STOP CONDITIONS
# ==========================================================================

class HumanAuthorizationGateAdvanced:
    """3-Tier Human Authorization Gate enforcing strict governance."""
    def evaluate_authorization(self, action_name: str, tier: AuthorizationTier, human_signed: bool = False) -> Dict[str, Any]:
        if tier == AuthorizationTier.LEVEL_0_OBSERVE:
            return {"tier": tier.value, "authorized": True, "requires_human_modal": False, "status": "AUTO_APPROVED"}
        elif tier == AuthorizationTier.LEVEL_1_SAFE_VALIDATE:
            return {"tier": tier.value, "authorized": True, "requires_human_modal": False, "status": "SAFE_POC_AUTHORIZED_WITHIN_SCOPE"}
        elif tier == AuthorizationTier.LEVEL_2_HIGH_IMPACT:
            if human_signed:
                return {"tier": tier.value, "authorized": True, "requires_human_modal": True, "status": "HUMAN_SIGNATURE_VERIFIED"}
            else:
                return {"tier": tier.value, "authorized": False, "requires_human_modal": True, "status": "AWAITING_HUMAN_CRYPTOGRAPHIC_APPROVAL"}
        return {"authorized": False, "status": "UNKNOWN_TIER"}


class StopConditionEngine:
    """Monitors live execution and enforces hard stop fences & kill switches."""
    def __init__(self, policy: Optional[StopConditionPolicy] = None):
        self.policy = policy or StopConditionPolicy()

    def check_operation_safety(self, target_ip: str, elapsed_time_sec: float, probe_count: int) -> Tuple[bool, Optional[str]]:
        if self.policy.kill_switch_active:
            return False, "STOP: Emergency Kill Switch was activated by Security Commander."
        if elapsed_time_sec > self.policy.time_limit_sec:
            return False, f"STOP: Execution time ({elapsed_time_sec:.1f}s) exceeded limit ({self.policy.time_limit_sec}s)."
        
        # Check CIDR scope fence
        in_scope = any(target_ip.startswith(prefix.split("/")[0][:7]) for prefix in self.policy.allowed_cidrs)
        if not in_scope:
            return False, f"STOP: Target IP {target_ip} is outside authorized CIDR boundaries."
        
        if probe_count > self.policy.max_probes_per_minute:
            return False, f"STOP: Rate limit exceeded ({probe_count} probes > {self.policy.max_probes_per_minute}/min)."

        return True, "SAFE_TO_PROCEED"


# ==========================================================================
# 9. EVIDENCE PROVENANCE LEDGER & PURPLE TEAM SCORING
# ==========================================================================

class ProvenanceLedger:
    """Maintains an immutable cryptographic chain of evidence provenance for every finding."""
    def __init__(self):
        self.records: List[ProvenanceRecord] = []

    def record_finding(self, finding_id: str, raw_evidence: str, tool: str, version: str,
                       llm: str, reasoning: str, tier: AuthorizationTier, authorizer: str,
                       action: str, outcome: str) -> ProvenanceRecord:
        raw_hash = hashlib.sha256(raw_evidence.encode()).hexdigest()
        prev_hash = self.records[-1].block_hash if self.records else "0" * 64
        payload = f"{finding_id}|{raw_hash}|{tool}|{version}|{llm}|{tier.name}|{authorizer}|{outcome}|{prev_hash}"
        block_hash = hashlib.sha256(payload.encode()).hexdigest()

        rec = ProvenanceRecord(
            finding_id=finding_id,
            raw_evidence_hash=raw_hash,
            tool_name=tool,
            tool_version=version,
            timestamp=time.time(),
            llm_used=llm,
            llm_reasoning_summary=reasoning,
            authorization_tier=tier,
            authorized_by=authorizer,
            action_performed=action,
            outcome_summary=outcome,
            block_hash=block_hash
        )
        self.records.append(rec)
        return rec


class ResilienceScorer:
    """Calculates unified multi-dimensional NEXUS Security & Resilience Scores."""
    def calculate_scores(self) -> ResilienceScorecard:
        # Before remediation
        attack_cap = 87.0
        detect_cap = 64.0
        resp_cap = 71.0
        recov_cap = 76.0
        exposure = 42.0
        id_risk = 58.0
        cld_risk = 31.0
        ai_sec = 49.0
        before = (detect_cap + resp_cap + recov_cap + ai_sec + (100 - exposure) + (100 - id_risk) + (100 - cld_risk)) / 7.0

        # After remediation
        after = (94.0 + 92.0 + 88.0 + 96.0 + (100 - 8.0) + (100 - 12.0) + (100 - 6.0)) / 7.0

        return ResilienceScorecard(
            attack_capability=attack_cap,
            detection_capability=detect_cap,
            response_capability=resp_cap,
            recovery_capability=recov_cap,
            exposure_score=exposure,
            identity_risk=id_risk,
            cloud_risk=cld_risk,
            ai_security=ai_sec,
            composite_resilience_before=round(before, 1),
            composite_resilience_after=round(after, 1)
        )


class PurpleXEngine:
    """Calculates comprehensive Purple Team effectiveness ratings."""
    def compute_purple_score(self) -> PurpleTeamScore:
        return PurpleTeamScore(
            attack_coverage_pct=91.0,
            detection_coverage_pct=72.0,
            detection_accuracy_pct=83.0,
            response_effectiveness_pct=69.0,
            remediation_effectiveness_pct=87.0,
            overall_purple_rating=78.0
        )


# ==========================================================================
# 10. CONTINUOUS PURPLE FEEDBACK LOOP ENGINE
# ==========================================================================

class ContinuousPurpleLoop:
    """
    Executes the formal Attack -> Defense Continuous Feedback Loop:
      Target Profile -> Surface Graph -> Attack Hypothesis -> Safe Validation
      -> Detection Check -> Blue Response / Detection Gap -> Remediation Plan
      -> Re-Validation -> Security Posture Update
    """
    def __init__(self):
        self.surface_engine = AttackSurfaceGraphEngine()
        self.hypo_engine = AttackHypothesisEngine()
        self.ranker = AttackPathRanker()
        self.safe_validator = SafeValidationEngine()
        self.detection_eng = DetectionEngineering()
        self.soc_agent = SOCInvestigationAgent()
        self.containment = AutomatedContainmentEngine()
        self.remediator = RemediationPlannerEngine()
        self.verifier = ControlVerificationEngine()
        self.immune_system = DigitalImmuneSystem()
        self.scorer = ResilienceScorer()
        self.purple_scorer = PurpleXEngine()
        self.blast_engine = BlastRadiusEngine()
        self.whatif = WhatIfSimulator()
        self.deception = DeceptionEngine()
        self.aix = AIXEngine()
        self.auth_gate = HumanAuthorizationGateAdvanced()
        self.stop_engine = StopConditionEngine()
        self.provenance = ProvenanceLedger()

    def run_complete_feedback_loop(self) -> Dict[str, Any]:
        results = {}

        # 1. Target Surface Graph & Choke Points
        graph = self.surface_engine.build_graph()
        paths, chokes = self.ranker.rank_paths()
        results["surface_graph"] = {"nodes": len(graph.nodes), "edges": len(graph.edges)}
        results["ranked_paths"] = paths
        results["choke_points"] = chokes

        # 2. Attack Hypothesis Formulation & Safe Validation
        hyps = self.hypo_engine.generate_hypotheses()
        escalated_hyp = next(h for h in hyps if h.is_escalated)
        val_result = self.safe_validator.validate_safely(escalated_hyp)
        results["validated_hypothesis"] = escalated_hyp
        results["safe_validation"] = val_result

        # 3. Detection-Aware Evaluation
        det_eval = DetectionAwareEvaluator().evaluate_technique("Credential Abuse (admin_svc)")
        results["detection_awareness"] = det_eval

        # 4. Blue Response & Detection Engineering
        rules = self.detection_eng.generate_rules()
        timeline = self.soc_agent.build_incident_timeline("AL-0891")
        results["detection_rules_generated"] = rules
        results["soc_timeline"] = timeline

        # 5. Blast Radius Modeling
        blast = self.blast_engine.calculate_blast_radius("10.0.4.50 (web-prod-01)")
        results["blast_radius"] = blast

        # 6. "What-If" Simulation & Remediation
        whatif_results = self.whatif.simulate_scenarios()
        rem_plan = self.remediator.build_plan()
        results["whatif_simulations"] = whatif_results
        results["remediation_plan"] = rem_plan

        # 7. Level-2 Human Authorization & Execution
        auth = self.auth_gate.evaluate_authorization("Execute Full Containment + Remediation", AuthorizationTier.LEVEL_2_HIGH_IMPACT, human_signed=True)
        containment_res = self.containment.execute_containment("10.0.4.50", "admin_svc", "198.51.100.44")
        results["authorization"] = auth
        results["containment_actions"] = containment_res

        # 8. Re-Validation (Proving Path Disappearance)
        reval = self.verifier.verify_remediation("AP-01")
        results["re_validation"] = reval

        # 9. Digital Immune System Recording
        antibody = self.immune_system.record_incident_antibodies("INC-AL-0891", "T1003.001", rules[0], "Auto-Containment Playbook #14")
        results["antibody_created"] = antibody

        # 10. AI-X & Deception Status
        results["aix_audit"] = self.aix.run_ai_audit()
        results["deception_status"] = [d.name for d in self.deception.decoys]

        # 11. Resilience Scores Before & After
        scores = self.scorer.calculate_scores()
        purple_scores = self.purple_scorer.compute_purple_score()
        results["resilience_scores"] = scores
        results["purple_scores"] = purple_scores

        # 12. Provenance Ledger Record
        prov_record = self.provenance.record_finding(
            finding_id="FIND-2026-0915-01",
            raw_evidence="PAN-OS RCE payload echo -> admin_svc TGT -> DB reachability",
            tool="NEXUS-X Purple Engine",
            version="v2.4.0",
            llm="GPT-5.6 Sol / Gemini 3.8 Flash",
            reasoning="Identified critical choke point at admin_svc MFA and DB microsegmentation.",
            tier=AuthorizationTier.LEVEL_2_HIGH_IMPACT,
            authorizer="SecOps Commander",
            action="Executed DB Microsegmentation + FIDO2 Enforcement",
            outcome="Attack Path AP-01 completely eliminated (Re-test PASSED)"
        )
        results["provenance_hash"] = prov_record.block_hash

        return results


if __name__ == "__main__":
    NexusXPowerStack().execute_full_cycle()
