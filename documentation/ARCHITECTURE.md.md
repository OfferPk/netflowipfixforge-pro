\# NetFlowIPFIXForge Pro \- Technical Architecture & Security Specification

\#\# 1\. Executive Summary

NetFlow v9 (RFC 3954\) and IPFIX (IP Flow Information Export / RFC 7011–7013) represent the global telemetry protocol standard for network traffic analysis, capacity planning, DDoS detection, network microsegmentation validation, and threat hunting across enterprise switches, routers, and cloud VPC infrastructures.

However, real-world flow monitoring deployments face severe technical and operational challenges:  
1\. \*\*Template Asynchrony & "Template Not Found" Decoder Drops\*\*:  
   Unlike NetFlow v5 (fixed 48-byte records), NetFlow v9 and IPFIX decouple schema definition from data transmission using Template FlowSets (Template ID \$\\ge 256\$). If the exporter template timeout is set too high (e.g. 30 minutes) or initial UDP packets are dropped, flow collectors (Elasticsearch, Splunk, Kentik, ntopng) cannot decode the raw binary stream, causing prolonged telemetry loss.  
2\. \*\*Integer Counter Rollover on 100G/400G Links\*\*:  
   Using legacy 32-bit \`octetDeltaCount\` (IE \#1) and \`packetDeltaCount\` (IE \#2) causes counters to roll over in less than 35 seconds at 1 Gbps, and in sub-second intervals at 100 Gbps, corrupting network bandwidth accounting.  
3\. \*\*Sampling Rate Dashboard Distortion\*\*:  
   To conserve CPU and collector bandwidth on high-throughput backbones, routers apply 1:N packet sampling (e.g. 1:1000). When exporters fail to transmit the RFC 7011 Option Template FlowSet defining the sampling interval, SIEM dashboards report traffic volume as 1,000x lower than reality.  
4\. \*\*Unencrypted Plaintext Flow Broadcast\*\*:  
   Exporting flow records over plaintext UDP (port 2055 or 4739\) leaks complete network topology, internal IP addressing, and port communications to passive eavesdroppers. RFC 7011 mandates IPFIX over DTLS or TLS for Zero-Trust environments.

NetFlowIPFIXForge Pro provides a 100% client-side studio and standalone DevSecOps CLI tool to model valid RFC 7011 IPFIX / NetFlow v9 packets, audit flow export configurations against a 10-point Zero-Trust rubric (0–100%, Grades A+ to F), and synthesize production configurations for Cisco Catalyst / IOS-XE Flexible NetFlow (FNF), Juniper Junos inline-jflow, Linux pmacct, Logstash, ntopng, and Python test senders.

\---

\#\# 2\. Protocol Standards & Packet Binary Structure

\#\#\# 2.1 RFC 7011 IPFIX Packet Layout  
An IPFIX Message consists of a 16-byte Message Header followed by one or more FlowSets (Template, Options Template, or Data):  
\`\`\`  
 0                   1                   2                   3  
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  
\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
|       Version Number (10)     |          Length               |  
\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
|                           Export Time                         |  
\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
|                       Sequence Number                         |  
\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
|                    Observation Domain ID                      |  
\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
\`\`\`

\#\#\# 2.2 Template FlowSet Structure  
\- \*\*Set ID\*\*: \`2\` for IPFIX (RFC 7011), \`0\` for NetFlow v9 (RFC 3954).  
\- \*\*Template Record\*\*:  
  \- \`Template ID\` (2 bytes, \$\\ge 256\$)  
  \- \`Field Count\` (2 bytes)  
  \- Array of \`\[Information Element ID (2 bytes), Field Length (2 bytes)\]\`  
  \- Optional Enterprise Bit: If set, high bit of Element ID is 1, followed by 4-byte Enterprise Number.

\---

\#\# 3\. 10-Point Zero-Trust Flow Telemetry Rubric

| \# | Security Control | Max Pts | Passing Requirement | Threat Mitigated |  
|---|------------------|---------|---------------------|------------------|  
| 1 | Transport Protocol Encryption | 15 | RFC 7011 DTLS or TLS (port 4740\) | Passive eavesdropping on network communication |  
| 2 | Observation Domain ID & Source Scoping | 15 | Domain ID \$\>0\$ \+ dedicated source IP | Multi-tenant collector template collision |  
| 3 | Template Refresh Cadence | 10 | \$\\le 60\$ seconds or \$\\le 1000\$ packets | "Template Not Found" decoder drops after reboot |  
| 4 | High-Precision 64-bit Timestamping | 10 | Millisecond epoch (\`flowStartMilliseconds\`) | Microburst forensic blindspots & timing skew |  
| 5 | 64-bit High-Capacity Volume Counters | 10 | 8-byte \`octetDeltaCount\` & \`packetDeltaCount\` | Integer counter wrapping on 100G/400G links |  
| 6 | Complete 5-Tuple Network Identification | 10 | Src/Dst IP, Protocol, Src/Dst Port | Incomplete network routing & port attribution |  
| 7 | Sampling Rate & Option Template Export | 10 | 1:1 unsampled OR Option Template export | 1000x traffic volume dashboard underreporting |  
| 8 | Bidirectional SNMP Interface Index | 10 | Both \`ingressInterface\` & \`egressInterface\` | Unidirectional port path blindness |  
| 9 | Collector Redundancy & Failover | 5 | Secondary collector configured | Single point of collector telemetry failure |  
| 10 | Flow Cache Aging & Table Protection | 5 | Active \$\\le 60\$s, Inactive \$\\le 15\$s | Router memory exhaustion during SYN flood attacks |

\---

\#\# 4\. Multi-Vendor Synthesizer Matrix

| Target Platform | Syntax Family | Key Configuration Directives |  
|-----------------|---------------|------------------------------|  
| \*\*Cisco IOS-XE\*\* | Flexible NetFlow (FNF) | \`flow record FNF\_REC\`, \`match\`, \`collect counter bytes long\`, \`flow exporter ... export-protocol ipfix\` |  
| \*\*Juniper Junos\*\* | Inline-jflow | \`set services flow-monitoring version-ipfix template ...\`, \`set forwarding-options sampling ...\` |  
| \*\*Linux pmacct\*\* | \`nfacctd.conf\` | \`nfacctd\_port: 2055\`, \`aggregate: src\_host, dst\_host, src\_port, dst\_port, proto\`, \`plugins: memory\` |  
| \*\*Logstash\*\* | \`10-netflow.conf\` | \`input { udp { port \=\> 2055 codec \=\> netflow { versions \=\> \[9, 10\] } } }\` |  
| \*\*ntopng / nProbe\*\*| \`nprobe.conf\` | \`-i=none \-n=\<host\>:\<port\> \-V=10 \-T="%IPV4\_SRC\_ADDR %IPV4\_DST\_ADDR %IN\_BYTES %IN\_PKTS"\` |  
| \*\*Python Client\*\* | Standalone Script | Raw struct packing for RFC 7011 Header, Template FlowSet 256, and Data FlowSet |  
