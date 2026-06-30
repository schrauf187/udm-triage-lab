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