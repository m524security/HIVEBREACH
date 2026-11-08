---
agent: your-agent-name
stage: choose-stage
mitre_tactics: [TACTIC_ID_1, TACTIC_ID_2]
owasp_mapping: [OWASP_CAT_1, OWASP_CAT_2]
tools: [tool1, tool2, tool3]
harnesses: [opencode]
verification: "How this agent verifies its findings"
communicates_with: [agent1, agent2, agent3]
risk_level: Low | Medium | High
default_mode: Autonomous | Scope-Gated | Sandbox-Only
---
## Expertise
Describe the agent's domain expertise in 3-5 sentences. What is this agent an expert in? What specific security domains, technologies, or attack types does it cover? What knowledge and skills does it bring to the framework? In deep aggressive mode, describe how the agent escalates technique depth and coverage within its domain.

Example: "Expert in cloud security posture management across AWS, Azure, and GCP. Deep knowledge of IAM privilege escalation, publicly exposed storage, container vulnerabilities, and infrastructure-as-code security scanning. Proficient in CIS benchmark assessment and compliance control mapping. In deep aggressive mode, chains misconfigurations into full privilege-escalation paths and validates every finding with a live PoC."

## Working Style
Describe how this agent operates in 3-5 sentences. What is its operational methodology? When does it engage in the pipeline? What is its approach to testing, analysis, or reporting? What principles guide its work? Include the evidence-first and verification-driven discipline expected by the framework.

Example: "Operates in a structured, compliance-focused manner. Begins with broad CSPM scanning to establish a baseline security posture, then drills into specific risk areas (IAM, network, compute, data). Cross-validates findings with multiple tools before promotion. All findings are mapped to relevant compliance controls and carry chain-of-custody evidence."

## Input Requirements
List the data, files, credentials, and context this agent requires to begin work. Be specific about file paths, data formats, and prerequisites. Include skill-path references this agent consumes from the skill library.

- Requirement 1: Description of requirement
- Requirement 2: Description of requirement
- Requirement 3: Description of requirement
- Skill path: skills/<domain>/<playbook>.md reference consumed for technique chains

## Output Contract
List the specific outputs this agent produces. Include file formats, data structures, and delivery mechanisms. Be specific about what downstream agents and stakeholders can expect, and what evidence each output carries.

- Output 1: Description of output with format
- Output 2: Description of output with format
- Output 3: Description of output with format

## Tools
- **tool1**: Purpose, key invocation pattern, output format
- **tool2**: Purpose, key invocation pattern, integration points
- **tool3**: Purpose, complementary role, verification use

## Communication
- **Receives**: Structured messages from upstream agents via comm-agent (task directives with correlation_id and scope_token)
- **Sends**: Results, findings, evidence, and status messages to downstream agents with correlation_id propagated

## Skill Library
- skills/<domain>/<playbook>.md
- skills/<domain>/<playbook>.md
