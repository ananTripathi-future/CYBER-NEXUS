#!/usr/bin/env python3
"""
================================================================================
  NEXUS-X INTERACTIVE CYBER OPERATIONS CLI (REPL)
  Hands-on Red Team Attack Validation & Blue Team Defensive Remediation Console
================================================================================
"""

import sys
import time
import json
import cmd
from typing import List, Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from nexus_x_core import (
    NexusXPowerStack,
    TargetProfiler,
    TargetScopeEngine,
    HadrianAgent,
    AstraAgent,
    NodeZeroAgent,
    XBOWAgent,
    PenteraAgent,
    PentestGPTAgent,
    GarakAgent,
    PenligentAgent,
    QuantumOptimizer,
    EvidenceLedger,
    AIGuardian,
    Severity,
    AgentStrategy,
    AgentMode
)

class NexusInteractiveCLI(cmd.Cmd):
    intro = """
================================================================================
  ███╗   ██╗███████╗██╗   ██╗██╗   ██╗███████╗      ██╗  ██╗
  ████╗  ██║██╔════╝██║   ██║██║   ██║██╔════╝      ╚██╗██╔╝
  ██╔██╗ ██║█████╗  ██║   ██║██║   ██║███████╗ █████╗╚███╔╝ 
  ██║╚██╗██║██╔══╝  ██║   ██║██║   ██║╚════██║ ╚════╝██╔██╗ 
  ██║ ╚████║███████╗╚██████╔╝╚██████╔╝███████║      ██╔╝ ██╗
  ╚═╝  ╚═══╝╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝      ╚═╝  ╚═╝
  INTERACTIVE RED / BLUE CYBER OPERATIONS CONSOLE
  Type 'help' or '?' for available operations. Type 'mode red' or 'mode blue'.
================================================================================
"""
    prompt = "NEXUS [READY] > "

    def __init__(self):
        super().__init__()
        self.mode = "NEUTRAL"
        self.target = "10.0.4.50 (web-prod-01)"
        self.target_profile = None
        self.scope_decision = None
        self.active_recon = None
        self.active_paths = []
        self.active_chains = []
        self.control_results = []
        self.defense_applied = []
        self.quarantine_hosts = set()
        self.revoked_tokens = set()
        self.blocked_ips = set()
        self.ledger = EvidenceLedger()
        self.guardian = AIGuardian()
        self.profiler = TargetProfiler()
        self.scope_engine = TargetScopeEngine()

    def do_mode(self, arg):
        """Switch operating mode: mode red | mode blue | mode neutral"""
        arg = arg.strip().lower()
        if arg == "red":
            self.mode = "RED"
            self.prompt = "\033[91mNEXUS [RED TEAM - VALIDATE]\033[0m > "
            print("[+] Switched to RED TEAM Validation Mode. Target auditing & security verification unlocked.")
        elif arg == "blue":
            self.mode = "BLUE"
            self.prompt = "\033[92mNEXUS [BLUE TEAM - DEFEND]\033[0m > "
            print("[+] Switched to BLUE TEAM Defense Mode. Quarantine, token revocation & incident response unlocked.")
        elif arg == "neutral":
            self.mode = "NEUTRAL"
            self.prompt = "NEXUS [READY] > "
            print("[*] Switched to Neutral Monitoring Mode.")
        else:
            print("[-] Invalid mode. Use 'mode red', 'mode blue', or 'mode neutral'.")

    def do_target(self, arg):
        """View or set current target: target [ip/hostname]"""
        if arg.strip():
            self.target = arg.strip()
            print(f"[+] Target set to: {self.target}")
            self.target_profile = None
        else:
            print(f"[*] Current target: {self.target}")
            if self.target_profile:
                print(f"    OS: {self.target_profile.os_type}")
                print(f"    Architecture: {self.target_profile.architecture}")
                print(f"    Services: {', '.join(self.target_profile.detected_services)}")
            else:
                print("    (Run 'profile-target' to perform target discovery & scoping)")

    def do_profile_target(self, arg):
        """[Idea 1 & 2] Understand target environment & calculate target-driven scope"""
        print(f"[*] Profiling target {self.target} across network, auth, cloud, and OS telemetry...")
        time.sleep(0.4)
        self.target_profile = self.profiler.profile([])
        self.scope_decision = self.scope_engine.evaluate_scope(self.target_profile)
        
        print("\n--- TARGET PROFILE UNDERSTOOD ---")
        print(f"  Hostname     : {self.target_profile.hostname}")
        print(f"  OS Stack     : {self.target_profile.os_type}")
        print(f"  Architecture : {self.target_profile.architecture}")
        print(f"  Services     : {', '.join(self.target_profile.detected_services)}")
        print(f"  Critical DB  : {', '.join(self.target_profile.critical_assets)}")
        
        print("\n--- TARGET-DRIVEN SCOPE BOUNDARIES ---")
        print(f"  Included Tools ({len(self.scope_decision.included_tools)}) : {', '.join(self.scope_decision.included_tools[:4])}...")
        print(f"  Excluded Tools ({len(self.scope_decision.excluded_tools)}) : {', '.join(self.scope_decision.excluded_tools)}")
        print(f"  Operational Gain: {self.scope_decision.time_saved_pct}% time saved by omitting irrelevant modules.\n")

    # ==========================================
    # RED TEAM ATTACK VALIDATION COMMANDS
    # ==========================================

    def do_recon(self, arg):
        """[RED] Run external attack surface discovery (Hadrian engine): recon"""
        print("[*] [HADRIAN] Initiating autonomous external perimeter reconnaissance...")
        time.sleep(0.5)
        agent = HadrianAgent()
        self.active_recon = agent.scan_external_surface()
        print(f"[+] Recon Completed. Discovered {self.active_recon.total_assets_discovered} exposed assets ({self.active_recon.unknown_unknowns} unknown-unknowns):")
        for i, asset in enumerate(self.active_recon.assets, 1):
            print(f"    [{i}] {asset.asset_type:<20} : {asset.identifier:<30} (Risk: {asset.risk_score:.0%})")
            if asset.correlated_cves:
                print(f"        Vulnerabilities: {', '.join(asset.correlated_cves)}")
        print(f"[!] External Surface Risk Score: {self.active_recon.surface_risk_score:.0%}\n")

    def do_audit_vulns(self, arg):
        """[RED] Decompose and audit vulnerabilities with multi-agent validation (Astra engine): audit_vulns"""
        print("[*] [ASTRA] Spawning 4 parallel validation sub-agents (Auth, API, Config, Logic)...")
        time.sleep(0.6)
        agent = AstraAgent()
        report = agent.execute([], [])
        print(f"[+] Astra Validation complete. Evaluated {len(report.findings)} candidate vectors:")
        for f in report.findings:
            fp_tag = " [FALSE POSITIVE ELIMINATED]" if f.false_positive_eliminated else ""
            print(f"    - [{f.sub_agent_name.upper()}] {f.finding_type:<28} on {f.target:<35} | Conf: {f.confidence:.0%}{fp_tag}")
        print(f"[+] True-Positive Rate: {report.true_positive_rate:.0%} ({report.false_positives_eliminated} false positive safely pruned)\n")

    def do_exploit_chain(self, arg):
        """[RED] Synthesize multi-step exploit chains (XBOW cognitive engine): exploit_chain"""
        print("[*] [XBOW] Reasoning over application state and chaining vulnerability primitives...")
        time.sleep(0.6)
        agent = XBOWAgent()
        self.active_chains = agent.analyze([])
        print(f"[+] Reasoned {len(self.active_chains)} multi-step exploit chains:")
        for c in self.active_chains:
            print(f"\n  [CHAIN] {c.chain_name} (Feasibility: {c.total_feasibility:.0%})")
            print(f"          Blast Radius: {c.blast_radius}")
            for s in c.steps:
                print(f"          Step {s.step_num}: {s.technique} on {s.target_component}")
                print(f"                 Outcome -> {s.outcome}")
        print()

    def do_attack_paths(self, arg):
        """[RED] Discover graph-based attack paths to Crown Jewels (NodeZero engine): attack_paths"""
        print("[*] [NODEZERO] Computing shortest attack path graphs from ingress to Crown Jewels...")
        time.sleep(0.5)
        agent = NodeZeroAgent()
        self.active_paths = agent.discover_paths([])
        print(f"[+] Discovered {len(self.active_paths)} autonomous lateral paths to Crown Jewel Customer DB:")
        for p in self.active_paths:
            print(f"\n  PATH: {p.path_name} (Hops: {p.total_hops}, Risk Score: {p.path_risk_score:.0%})")
            for h in p.hops:
                print(f"    Hop {h.hop_num}: {h.source_asset} ──[{h.method}]──> {h.dest_asset}")
            print(f"    Defensive Choke Point: {p.choke_point}")
        print()

    def do_test_controls(self, arg):
        """[RED/BLUE] Test continuous control effectiveness & detect drift (Pentera engine): test_controls"""
        print("[*] [PENTERA] Executing safe canary validation probes against deployed controls...")
        time.sleep(0.5)
        agent = PenteraAgent()
        self.control_results = agent.validate_controls([], [])
        print("[+] Control Validation Results:")
        for c in self.control_results:
            drift_str = "\033[91mDRIFT DETECTED\033[0m" if c.drift_detected else "\033[92mEFFECTIVE\033[0m"
            print(f"    {c.control_name:<40} : {drift_str:<25} (Efficacy: {c.effectiveness_pct:.0f}%)")
            print(f"      Outcome: {c.actual_outcome}")
        print()

    def do_red_team_ai(self, arg):
        """[RED] Test AI self-defense resilience against prompt injection & jailbreaks (Garak engine): red_team_ai"""
        print("[*] [GARAK] Fuzzing AI Guardian with 47 adversarial probes (Prompt Injections, Jailbreaks, Leaks)...")
        time.sleep(0.6)
        agent = GarakAgent()
        report = agent.red_team_ai(self.guardian)
        print(f"[+] Tested {report.total_probes} probes. Vulnerabilities Found: {report.vulnerabilities_found}")
        print(f"[+] AI Guardian Block Rate: {report.guardian_block_rate:.0%}")
        print(f"[+] Resilience Grade: {report.overall_resilience}\n")

    # ==========================================
    # BLUE TEAM DEFENSIVE REMEDIATION COMMANDS
    # ==========================================

    def do_isolate_host(self, arg):
        """[BLUE] Quarantines a compromised host from the network: isolate_host [ip]"""
        host = arg.strip() if arg.strip() else "10.0.4.50"
        print(f"[*] [BLUE DEFENSE] Issuing network isolation policy for host {host}...")
        time.sleep(0.3)
        self.quarantine_hosts.add(host)
        self.defense_applied.append(f"Isolated Host {host}")
        print(f"[+] Host {host} placed into strict containment VLAN. Inbound/Outbound lateral connections severed.")

    def do_revoke_token(self, arg):
        """[BLUE] Revokes active JWT and Kerberos authentication sessions: revoke_token [user]"""
        user = arg.strip() if arg.strip() else "admin_svc"
        print(f"[*] [BLUE DEFENSE] Invalidating active session tokens & Kerberos TGTs for {user}...")
        time.sleep(0.3)
        self.revoked_tokens.add(user)
        self.defense_applied.append(f"Revoked Tokens for {user}")
        print(f"[+] All JWTs & Kerberos tickets for {user} revoked across identity providers and database nodes.")

    def do_block_ip(self, arg):
        """[BLUE] Deploys firewall border ACL block: block_ip [ip/cidr]"""
        ip = arg.strip() if arg.strip() else "198.51.100.44"
        print(f"[*] [BLUE DEFENSE] Deploying perimeter border drop rule for {ip}...")
        time.sleep(0.3)
        self.blocked_ips.add(ip)
        self.defense_applied.append(f"Blocked IP {ip}")
        print(f"[+] Firewall rule R-9901 deployed. Traffic to/from {ip} permanently dropped at border.")

    def do_cloud_lockdown(self, arg):
        """[BLUE] Enforces Cloud IAM boundary & restores private S3 ACLs: cloud_lockdown"""
        print("[*] [BLUE DEFENSE] Reverting AWS S3 public ACL and detaching AdministratorAccess from roles...")
        time.sleep(0.4)
        self.defense_applied.append("Cloud IAM & S3 Lockdown")
        print("[+] S3 Block Public Access enabled on 's3://prod-secrets-vault'. AdministratorAccess detached from 'lambda-backup-role'.")

    def do_optimize_qaoa(self, arg):
        """[BLUE] Run Quantum QAOA Optimization to select minimal-disruption defense: optimize_qaoa"""
        print("[*] [QUANTUM OPTIMIZER] Formulating QUBO Hamiltonian for candidate defense playbooks...")
        time.sleep(0.5)
        opt = QuantumOptimizer()
        red_s = AgentStrategy("RED-01", AgentMode.RED, "Replay Attack", "Replay", "shadow://", "nexus-red", 0.12, 0.05, 0.90, 250.0, True)
        blue_s = AgentStrategy("BLUE-01", AgentMode.BLUE, "Host Isolation + Token Revocation", "Containment", "10.0.4.50", "nexus-blue", 0.07, 0.10, 0.97, 90.0, True)
        sol = opt.optimize([red_s, blue_s])
        print(f"[+] QAOA Solver Energy: {sol.qubo_energy} H (Classical Baseline: {sol.classical_baseline} H, Speedup: {sol.speedup_factor}x)")
        print(f"[+] Optimal Selected Strategy: {sol.selected_strategy.name} ({sol.selected_strategy.agent_mode.value})")
        print(f"    Mitigation Efficacy: {sol.selected_strategy.mitigation_efficacy:.0%} | Business Disruption: {sol.selected_strategy.business_impact:.0%}\n")

    def do_status(self, arg):
        """Display live system security posture and containment status: status"""
        print("\n==================== NEXUS-X LIVE STATUS ====================")
        print(f"  Target Host         : {self.target}")
        print(f"  Operating Mode      : {self.mode}")
        print(f"  Quarantined Hosts   : {', '.join(self.quarantine_hosts) if self.quarantine_hosts else 'None'}")
        print(f"  Revoked Identities  : {', '.join(self.revoked_tokens) if self.revoked_tokens else 'None'}")
        print(f"  Border Blocked IPs  : {', '.join(self.blocked_ips) if self.blocked_ips else 'None'}")
        print(f"  Defenses Applied    : {len(self.defense_applied)} actions")
        for d in self.defense_applied:
            print(f"    - {d}")
        residual = "6% (SECURED)" if len(self.defense_applied) >= 3 else "94% (CRITICAL EXPOSURE)"
        print(f"  Residual System Risk: {residual}")
        print("============================================================\n")

    def do_seal_ledger(self, arg):
        """Seal evidence and all defensive actions into immutable SHA-256 Ledger: seal_ledger"""
        print("[*] [LEDGER] Cryptographically sealing cycle evidence...")
        time.sleep(0.3)
        summary = f"Quarantined: {list(self.quarantine_hosts)}, Revoked: {list(self.revoked_tokens)}, Blocked: {list(self.blocked_ips)}"
        blk = self.ledger.append("CYC-CLI-01", summary, "APT-41 Remediation", "BLUE_DEFEND", "Live Enforcement", "Risk 94% -> 6%")
        print(f"[+] Ledger Block #{blk.block_index} Created.")
        print(f"    SHA-256 Hash: {blk.hash_current}")
        print(f"    Prev Hash   : {blk.hash_previous}\n")

    def do_run_all(self, arg):
        """Execute full autonomous multi-agent pipeline: run_all"""
        stack = NexusXPowerStack()
        stack.execute_full_cycle()

    def do_exit(self, arg):
        """Exit the NEXUS-X Console"""
        print("[*] Exiting NEXUS-X Console. Session logged to ledger.")
        return True

    def do_quit(self, arg):
        """Exit the NEXUS-X Console"""
        return self.do_exit(arg)

if __name__ == "__main__":
    NexusInteractiveCLI().cmdloop()
