## Privacy, Data Handling, and AI Provider Notice

UDM Triage Lab is an experimental SOC triage MVP. It uses a UDM-style evidence model, ontology enrichment, MITRE ATT&CK context, attack-path hypothesis logic, validation hunting queries, and AI-assisted reasoning.

### Important usage warning

Do not paste real customer-sensitive data, regulated data, patient data, personal data, secrets, credentials, production incident data, or confidential logs into this application unless the environment, data-processing terms, and customer approval explicitly allow it.

For demo and testing, use mock data or anonymized data.

### External AI processing

This MVP currently uses the Anthropic Claude API as the external AI inference provider.

When the AI triage, re-evaluation, or CTI research features are used, selected input data is sent to Anthropic for processing. According to Anthropic’s published privacy documentation for commercial/API products:

- Inputs and outputs from commercial products such as the Anthropic API are not used for model training by default.
- API inputs and outputs are automatically deleted from Anthropic’s backend within 30 days under standard retention, except for listed cases such as usage-policy enforcement, legal obligations, longer-retention services, or separate agreements.

Users should review Anthropic’s current privacy and data retention documentation before using this application with sensitive data.

### CTI Internet Research

The CTI Internet Research feature is optional and must be triggered manually by the analyst.

When enabled, the application is designed to send only selected internet-searchable indicators for research:

Allowed for CTI research:

- Public IP addresses
- Domains
- URLs
- File hashes
- MITRE technique IDs and technique names
- Sanitized command-line patterns

Not allowed for CTI research:

- Hostnames
- Usernames
- Email addresses
- Local file paths
- Process full paths
- Customer names
- Raw command lines containing local paths or sensitive filenames
- Internal/private IP addresses
- Patient/client-sensitive values
- Any data that may reveal regulated or confidential information

The purpose of CTI research is to enrich triage with external context. CTI findings do not automatically confirm compromise. They must be interpreted together with host evidence, alert evidence, and analyst validation.

### No automatic live environment access

The application does not directly connect to Microsoft Sentinel, CrowdStrike, Splunk, Google SecOps, Recorded Future, VirusTotal, or customer environments unless such integrations are explicitly implemented.

Generated hunting queries must be run by the analyst in the relevant security platform.

### Current MVP limitations

This MVP is not a production SOC system. It is a research and prototyping tool for:

- UDM-style alert normalization
- Ontology-guided triage reasoning
- MITRE ATT&CK interpretation
- Attack-path hypothesis generation
- Validation hunt generation
- AI-assisted triage and re-evaluation

All AI output must be reviewed by a qualified analyst.
## New Feature:
## Auto Alert Extractor and AI-Assisted UDM Mapping

The Auto Alert Extractor allows an analyst to paste raw security alert data from security products such as CrowdStrike Falcon, Microsoft Defender, Microsoft Sentinel, Splunk, Palo Alto, Zscaler, and similar platforms.

The extractor is designed to help analysts convert raw alert data into a validated UDM-style evidence bundle.

### What the Auto Alert Extractor does

The extractor can process:

- Raw JSON alerts
- Key-value alert dumps
- Vendor detection text
- SIEM alert exports
- EDR alert details
- Proxy, DNS, email, identity, and cloud alert data

The application locally extracts and flattens available fields, then uses AI to suggest possible UDM mappings.

The AI may recommend mappings such as:

- Alert name → `security_result.rule_name`
- Alert severity → `security_result.severity`
- Detection description → `security_result.description`
- Host name → `principal.asset.hostname`
- User name → `principal.user.userid`
- Source IP → `principal.ip`
- Destination IP/domain/URL → `target.ip`, `target.domain.name`, `target.url`
- Process path → `principal.process.file.full_path`
- Command line → `principal.process.command_line`
- File hash → `process.file.sha256` or `file.sha256`
- Vendor-specific values → `additional.fields.*`

### Human validation is mandatory

The Auto Alert Extractor provides recommendations only.

The analyst remains the final authority.

Each suggested mapping should be reviewed before it is used in the final UDM Analytics Evidence Bundle. The analyst may:

- Accept the suggested mapping
- Edit the suggested UDM field
- Reject the mapping
- Preserve the field as vendor-specific additional evidence

Only analyst-approved mappings should be used for final triage.

### Data sent to AI inference

When the Auto Alert Extractor is used, the pasted alert content may be sent to the configured AI inference provider for extraction and mapping assistance.

This is different from CTI Internet Research.

Auto Alert Extractor:

- Sends alert content to AI for field extraction and UDM mapping
- Does not perform internet research
- Does not look up indicators externally unless the analyst separately runs CTI research

CTI Internet Research:

- Sends only selected public indicators such as public IPs, domains, URLs, hashes, and sanitized command-line patterns
- Uses internet research
- Is optional and manually triggered

### Demo / NFR usage

For demo environments, NFR environments, synthetic alerts, and non-customer data, the Auto Alert Extractor can be used to accelerate mapping and testing.

Do not use real customer-sensitive data unless the environment, data-processing terms, and customer approval allow it.

### Sensitive data considerations

Raw alerts may contain sensitive values such as:

- Customer IDs
- Tenant IDs
- Subscription IDs
- Detection URLs
- Usernames
- Email addresses
- Hostnames
- Internal IPs
- Agent IDs
- File paths
- Raw command lines
- Case IDs
- Query text
- Compressed or encoded alert evidence

These fields may be useful for mapping and traceability, but they should be handled carefully.

Future privacy guardrails may include:

- Local sensitive-field detection
- Masking or redaction before AI processing
- Analyst approval before sending raw values
- DLP-like checks for personal or customer-sensitive data
- Separate demo mode and customer mode
- Audit trail of AI suggestions and analyst-approved mappings

### Traceability

The original alert evidence should be preserved for traceability.

The final UDM Analytics Evidence Bundle should include only validated mappings, while unmapped or vendor-specific fields can be preserved as additional evidence where useful.