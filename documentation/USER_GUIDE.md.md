\# NetFlowIPFIXForge Pro \- User Guide & DevSecOps Integration Manual

\#\# 1\. Web Studio Quickstart

1\. Open \`source-code/index.html\` in any modern web browser.  
2\. Select an industry preset from the top dropdown:  
   \- \*\*Enterprise Zero-Trust RFC 7011 IPFIX / DTLS Telemetry (A+)\*\*: IPFIX over DTLS port 4740, 64-bit millisecond timestamps, 64-bit counters, and Option Template sampling attribution.  
   \- \*\*Cloud VPC High-Capacity 100G Backbone Telemetry (A+)\*\*: 1:1000 sampled IPFIX telemetry with Option Template and Logstash/Elasticsearch ingestion.  
   \- \*\*Vulnerable Legacy NetFlow (Cleartext UDP 2055 / 32-bit) (F)\*\*: Demonstrates vulnerabilities from 32-bit counter wrapping, 30-minute template timeouts, and unencrypted UDP broadcast.  
3\. Review the \*\*Template FlowSet & Information Element (IE) Builder\*\*:  
   \- Customize Information Elements (Src/Dst IP, Port, Protocol, TCP Flags, Counters, Timestamps).  
   \- Toggle field lengths (e.g. 4 bytes vs 8 bytes for 64-bit counters).  
4\. Review the \*\*10-Point Zero-Trust Scorecard\*\* for network monitoring hygiene and security compliance.  
5\. Inspect the \*\*RFC 7011 Binary Wireframe & Hex Dump\*\*:  
   \- View byte-by-byte visual layout of Packet Header, Template FlowSet, and Data FlowSet.  
6\. Switch between synthesizer tabs to export configurations:  
   \- \*\*Cisco Catalyst / IOS-XE\*\*: Production Flexible NetFlow (FNF) CLI syntax.  
   \- \*\*Juniper Junos\*\*: Inline-jflow \`set\` commands.  
   \- \*\*Linux pmacct\*\*: \`nfacctd.conf\` daemon configuration.  
   \- \*\*Logstash\*\*: NetFlow codec input pipeline.  
   \- \*\*ntopng / nProbe\*\*: \`nprobe.conf\` parameters.  
   \- \*\*Python Test Client\*\*: Ready-to-run raw UDP packet sender script.

\---

\#\# 2\. DevSecOps CLI Tool (\`netflowforge-cli.py\`)

The standalone Python CLI tool requires zero external dependencies and runs on Python 3.8+.

\#\#\# 2.1 Searching IANA Information Elements  
\`\`\`bash  
\# Search by element name  
python3 build/netflowforge-cli.py ie \-q octet

\# Search by numeric ID  
python3 build/netflowforge-cli.py ie \-q 152  
\`\`\`

\#\#\# 2.2 Linting Flow Configurations & Templates  
\`\`\`bash  
python3 build/netflowforge-cli.py lint \-p presets/enterprise-zerotrust-ipfix-dtls.json  
\`\`\`  
Output:  
\`\`\`  
\[LINT PASS\] Configuration: Enterprise Zero-Trust RFC 7011 IPFIX / DTLS Telemetry  
  Protocol: ipfix (v10)  
  Template ID: 256, Fields: 12, Record Length: 55 bytes  
\`\`\`

\#\#\# 2.3 Running CI/CD Pipeline Security Audits  
\`\`\`bash  
\# Clean production flow configuration \-\> Exits code 0  
python3 build/netflowforge-cli.py audit \-p presets/enterprise-zerotrust-ipfix-dtls.json \--strict

\# Vulnerable flow configuration \-\> Exits code 1 (Pipeline Fails)  
python3 build/netflowforge-cli.py audit \-p presets/vulnerable-legacy-netflow-v5.json \--strict  
\`\`\`

\#\#\# 2.4 Synthesizing Multi-Vendor Configurations  
\`\`\`bash  
\# Generate Cisco FNF configuration  
python3 build/netflowforge-cli.py synthesize \-p presets/enterprise-zerotrust-ipfix-dtls.json \-f cisco

\# Generate Juniper Junos configuration  
python3 build/netflowforge-cli.py synthesize \-p presets/enterprise-zerotrust-ipfix-dtls.json \-f juniper  
\`\`\`

\---

\#\# 3\. GitHub Actions CI/CD Pipeline Template

Add this workflow to your NetDevOps or Ansible infrastructure repository (\`.github/workflows/flow-telemetry-gate.yml\`):

\`\`\`yaml  
name: Zero-Trust NetFlow & IPFIX Policy CI/CD Gate

on:  
  pull\_request:  
    paths:  
      \- 'netflow/\*\*'  
      \- 'ipfix/\*\*'  
      \- 'cisco/fnf/\*\*'  
      \- 'telemetry/\*\*'

jobs:  
  flow-security-audit:  
    runs-on: ubuntu-latest  
    steps:  
      \- name: Checkout Code  
        uses: actions/checkout@v4

      \- name: Set up Python  
        uses: actions/setup-python@v5  
        with:  
          python-version: '3.11'

      \- name: Audit Flow Exporter Configuration (Strict Gate)  
        run: |  
          python3 build/netflowforge-cli.py audit \-p presets/enterprise-zerotrust-ipfix-dtls.json \--strict  
\`\`\`  
