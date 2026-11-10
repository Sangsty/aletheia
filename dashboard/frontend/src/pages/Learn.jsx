/**
 * Static reference content. Every entry here mirrors the real RULES
 * table in pipeline/classifier/rule_classifier.py — technique IDs,
 * severities, and matcher logic are copied from that source, not
 * guessed, since getting a MITRE mapping wrong here is exactly the
 * kind of thing a report reviewer would catch.
 */
const TECHNIQUES = [
  {
    attack_type: "cryptominer_installation",
    label: "Cryptominer Installation",
    severity: "critical",
    ids: [{ id: "T1496", name: "Resource Hijacking" }],
    detected_when:
      "Commands match known cryptomining tool signatures (xmrig, minerd, stratum+tcp, cpuminer, xmr-stak, cryptonight, moneroocean).",
    meaning:
      "The attacker is trying to hijack this machine's CPU to mine cryptocurrency for themselves.",
  },
  {
    attack_type: "reverse_shell",
    label: "Reverse Shell",
    severity: "critical",
    ids: [
      { id: "T1059", name: "Command and Scripting Interpreter" },
      { id: "T1071", name: "Application Layer Protocol" },
    ],
    detected_when:
      "Shell patterns like sh -i, nc -e, /dev/tcp/, socat ... exec, or inline Python/Perl socket code.",
    meaning:
      "The attacker is opening an interactive remote shell back to a machine they control — persistent, hands-on-keyboard access.",
  },
  {
    attack_type: "data_exfiltration",
    label: "Data Exfiltration",
    severity: "critical",
    ids: [
      { id: "T1041", name: "Exfiltration Over C2 Channel" },
      { id: "T1048", name: "Exfiltration Over Alternative Protocol" },
    ],
    detected_when:
      "Commands that upload data out: curl -F/--upload-file/-T, curl -X POST, wget --post-, scp, rsync, or piping tar/base64 into nc/ssh/curl.",
    meaning: "The attacker is copying data off this machine to somewhere they control.",
  },
  {
    attack_type: "botnet_recruitment",
    label: "Botnet Recruitment",
    severity: "critical",
    ids: [
      { id: "T1071", name: "Application Layer Protocol" },
      { id: "T1584", name: "Compromise Infrastructure" },
    ],
    detected_when: "IRC, Mirai, Gafgyt, Qbot, busybox, or DDoS-related command strings.",
    meaning: "The session is trying to enlist this machine into a botnet for DDoS or further scanning.",
  },
  {
    attack_type: "privilege_escalation",
    label: "Privilege Escalation",
    severity: "critical",
    ids: [
      { id: "T1548", name: "Abuse Elevation Control Mechanism" },
      { id: "T1068", name: "Exploitation for Privilege Escalation" },
    ],
    detected_when:
      "sudo -l, sudo su, chmod u+s/4xxx, SUID search (find / -perm -4000), /etc/sudoers, visudo, pkexec, su root.",
    meaning: "The attacker is trying to go from limited access to full root control.",
  },
  {
    attack_type: "malware_deployment",
    label: "Malware Deployment",
    severity: "high",
    ids: [
      { id: "T1059.004", name: "Command and Scripting Interpreter: Unix Shell" },
      { id: "T1105", name: "Ingress Tool Transfer" },
    ],
    detected_when:
      "A download (wget/curl) followed by chmod +x or executing it (./something) — or Cowrie actually captured a file upload/download artifact.",
    meaning: "The attacker is delivering and running their own payload on this machine.",
  },
  {
    attack_type: "persistence_mechanism",
    label: "Persistence Mechanism",
    severity: "high",
    ids: [{ id: "T1053", name: "Scheduled Task/Job" }],
    detected_when:
      "crontab -e/-l, appending to /etc/crontab or /etc/rc.local, systemctl enable, appending to .bashrc/.profile, writing authorized_keys, or creating a new user.",
    meaning: "The attacker is making sure their access survives a reboot or session close.",
  },
  {
    attack_type: "defense_evasion",
    label: "Defense Evasion",
    severity: "high",
    ids: [
      { id: "T1070", name: "Indicator Removal" },
      { id: "T1222", name: "File and Directory Permissions Modification" },
    ],
    detected_when:
      "history -c, unsetting HISTFILE, HISTSIZE=0, deleting/overwriting .bash_history, shred, clearing /var/log, or flipping the immutable/append-only file attribute with chattr.",
    meaning: "The attacker is covering their tracks — erasing evidence of what they just did.",
  },
  {
    attack_type: "reconnaissance",
    label: "Reconnaissance",
    severity: "medium",
    ids: [
      { id: "T1082", name: "System Information Discovery" },
      { id: "T1497", name: "Virtualization/Sandbox Evasion" },
    ],
    detected_when:
      "Basic system-info commands (whoami, uname, ifconfig, ip, cat, ls, id, pwd, hostname, ps, netstat), or a hex-encoded echo string used to fingerprint the shell/environment.",
    meaning: "The attacker is scoping out what kind of machine they've landed on before deciding what to do next.",
  },
  {
    attack_type: "credential_brute_force",
    label: "Credential Brute Force",
    severity: "low",
    ids: [{ id: "T1110", name: "Brute Force" }],
    detected_when: "3 or more login attempts in one session.",
    meaning: "Classic automated password-guessing.",
  },
  {
    attack_type: "single_credential_probe",
    label: "Single Credential Probe",
    severity: "low",
    ids: [{ id: "T1110", name: "Brute Force" }],
    detected_when: "Exactly one login attempt, and no shell commands ran at all.",
    meaning: "An opportunistic single-shot login try — not sustained enough to count as brute force.",
  },
  {
    attack_type: "banner_grab",
    label: "Banner Grab",
    severity: "low",
    ids: [{ id: "T1595", name: "Active Scanning" }],
    detected_when: "The connection opened and closed with zero commands and zero credential attempts.",
    meaning:
      "The scanner read Cowrie's SSH banner/version and moved on without even trying to log in — typical of mass internet-wide scanners.",
  },
  {
    attack_type: "shell_verification_probe",
    label: "Shell Verification Probe",
    severity: "low",
    ids: [{ id: "T1059", name: "Command and Scripting Interpreter" }],
    detected_when: "Exactly one command, a plain echo <token>.",
    meaning:
      "The classic \"is this shell actually alive and responsive\" check bots run before committing to a real payload.",
  },
  {
    attack_type: "unclassified",
    label: "Unclassified",
    severity: "low",
    ids: [],
    detected_when: "None of the 13 rules above matched.",
    meaning:
      "Doesn't mean nothing happened — the session just didn't match any current signature. Could be a genuinely novel technique, or noise that doesn't fit the ruleset yet.",
  },
];

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

export default function Learn() {
  return (
    <div className="page">
      <div className="about-hero">
        <h2>Learn: attack types &amp; MITRE ATT&amp;CK</h2>
        <p>
          Aletheia's classifier is rule-based: every session's command sequence is
          checked against a fixed set of signatures, and the first one that matches
          decides the attack type, severity, and ATT&amp;CK technique IDs below. This
          page documents that real mapping — not an approximation of it.
        </p>
      </div>

      {SEVERITY_ORDER.map((tier) => (
        <div key={tier}>
          <h3 className={`section-heading severity-heading severity-${tier}`}>
            {tier} severity
          </h3>
          <div className="learn-cards">
            {TECHNIQUES.filter((t) => t.severity === tier).map((t) => (
              <div className="learn-card" key={t.attack_type}>
                <div className="learn-card-header">
                  <span className="learn-card-label">{t.label}</span>
                  <span className={`severity-pill severity-${t.severity}`}>{t.severity}</span>
                </div>
                <div className="technique-badges">
                  {t.ids.length === 0 ? (
                    <span className="technique-badge technique-badge-none">no ATT&amp;CK ID</span>
                  ) : (
                    t.ids.map((tid) => (
                      <a
                        key={tid.id}
                        className="technique-badge"
                        href={`https://attack.mitre.org/techniques/${tid.id.split(".")[0]}/`}
                        target="_blank"
                        rel="noreferrer"
                        title={tid.name}
                      >
                        {tid.id}
                      </a>
                    ))
                  )}
                </div>
                <div className="learn-card-row">
                  <span className="learn-card-row-label">Detected when:</span> {t.detected_when}
                </div>
                <div className="learn-card-row">
                  <span className="learn-card-row-label">What it means:</span> {t.meaning}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
