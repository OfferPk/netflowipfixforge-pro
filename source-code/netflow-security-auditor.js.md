/\*\*  
 \* NetFlowIPFIXForge Pro \- 10-Point Zero-Trust Flow Telemetry Security Auditor  
 \* Evaluates NetFlow v9 and IPFIX exporter configurations, template structures, and transport parameters (0-100%, Grades A+ to F).  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.NetFlowSecurityAuditor \= factory();  
  }  
}(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  function auditFlowConfiguration(config) {  
    const cfg \= config || {};  
    const checks \= \[\];  
    let totalScore \= 0;  
    const maxScore \= 100;

    // 1\. Transport Security Protocol (15 pts)  
    const transport \= (cfg.transport || 'dtls').toLowerCase();  
    const port \= parseInt(cfg.port || 4740, 10);  
    if (transport \=== 'dtls' || transport \=== 'tls') {  
      checks.push({  
        id: 'transport\_security',  
        name: 'Transport Encryption (RFC 7011 DTLS / TLS)',  
        score: 15,  
        maxScore: 15,  
        status: 'PASS',  
        details: \`Encrypted \${transport.toUpperCase()} transport on port \${port}. Flow telemetry is cryptographically protected against eavesdropping and path spoofing.\`  
      });  
      totalScore \+= 15;  
    } else if (transport \=== 'tcp') {  
      checks.push({  
        id: 'transport\_security',  
        name: 'Transport Encryption (RFC 7011 DTLS / TLS)',  
        score: 5,  
        maxScore: 15,  
        status: 'WARN',  
        details: \`Unencrypted TCP transport on port \${port}. Provides stream retransmission but leaves network communication graphs exposed to wire-sniffing.\`  
      });  
      totalScore \+= 5;  
    } else {  
      checks.push({  
        id: 'transport\_security',  
        name: 'Transport Encryption (RFC 7011 DTLS / TLS)',  
        score: 0,  
        maxScore: 15,  
        status: 'FAIL',  
        details: \`Insecure plaintext UDP transport on port \${port}. Network topology, internal IPs, and port activity are broadcast in plaintext with zero authentication.\`  
      });  
    }

    // 2\. Exporter Identity & Observation Domain Scoping (15 pts)  
    const obsDomain \= parseInt(cfg.observationDomainId \!== undefined ? cfg.observationDomainId : 1, 10);  
    const hasSourceIp \= \!\!cfg.exporterSourceIp;  
    if (obsDomain \> 0 && hasSourceIp) {  
      checks.push({  
        id: 'observation\_domain',  
        name: 'Observation Domain ID & Source Scoping',  
        score: 15,  
        maxScore: 15,  
        status: 'PASS',  
        details: \`Dedicated Observation Domain ID (\${obsDomain}) and source IP interface configured. Eliminates multi-device template collision.\`  
      });  
      totalScore \+= 15;  
    } else if (obsDomain \> 0\) {  
      checks.push({  
        id: 'observation\_domain',  
        name: 'Observation Domain ID & Source Scoping',  
        score: 8,  
        maxScore: 15,  
        status: 'WARN',  
        details: \`Observation Domain ID (\${obsDomain}) configured, but explicit exporter source loopback IP is omitted. Exporter IP may flap during interface state changes.\`  
      });  
      totalScore \+= 8;  
    } else {  
      checks.push({  
        id: 'observation\_domain',  
        name: 'Observation Domain ID & Source Scoping',  
        score: 0,  
        maxScore: 15,  
        status: 'FAIL',  
        details: 'Observation Domain ID is set to 0\. Causes collector template namespace collisions in multi-tenant environments.'  
      });  
    }

    // 3\. Template Refresh Cadence & Ingest Timeout (10 pts)  
    const templateTimeout \= parseInt(cfg.templateTimeoutSeconds || 60, 10);  
    const templateRatePackets \= parseInt(cfg.templateRatePackets || 1000, 10);  
    if (templateTimeout \<= 60 && templateRatePackets \<= 1000\) {  
      checks.push({  
        id: 'template\_cadence',  
        name: 'Template Refresh Cadence (\<=60s / \<=1000 pkts)',  
        score: 10,  
        maxScore: 10,  
        status: 'PASS',  
        details: \`Frequent template refresh (\${templateTimeout}s / \${templateRatePackets} pkts). Eliminates "Template Not Found" collector decoder errors after reboots.\`  
      });  
      totalScore \+= 10;  
    } else if (templateTimeout \<= 300\) {  
      checks.push({  
        id: 'template\_cadence',  
        name: 'Template Refresh Cadence (\<=60s / \<=1000 pkts)',  
        score: 5,  
        maxScore: 10,  
        status: 'WARN',  
        details: \`Template refresh timeout of \${templateTimeout}s is high. Collector may drop initial bursts of flow records during collector restarts.\`  
      });  
      totalScore \+= 5;  
    } else {  
      checks.push({  
        id: 'template\_cadence',  
        name: 'Template Refresh Cadence (\<=60s / \<=1000 pkts)',  
        score: 0,  
        maxScore: 10,  
        status: 'FAIL',  
        details: \`Excessive template timeout (\${templateTimeout}s). Causes prolonged telemetry blackouts if template packet is dropped.\`  
      });  
    }

    // 4\. High-Precision 64-bit Timestamping (10 pts)  
    const fields \= cfg.fields || \[\];  
    const hasMillisecondTs \= fields.some(f \=\> (f.id \=== 152 || f.id \=== 153\) && (f.length \=== 8));  
    const hasSecondsTs \= fields.some(f \=\> (f.id \=== 150 || f.id \=== 151));  
    if (hasMillisecondTs) {  
      checks.push({  
        id: 'timestamp\_precision',  
        name: 'High-Precision 64-bit Millisecond Timestamps',  
        score: 10,  
        maxScore: 10,  
        status: 'PASS',  
        details: 'Millisecond epoch timestamps (IE \#152/\#153, 8 octets) enabled. Essential for precise microburst forensics and SIEM incident correlation.'  
      });  
      totalScore \+= 10;  
    } else if (hasSecondsTs) {  
      checks.push({  
        id: 'timestamp\_precision',  
        name: 'High-Precision 64-bit Millisecond Timestamps',  
        score: 5,  
        maxScore: 10,  
        status: 'WARN',  
        details: 'Seconds-only epoch timestamps (IE \#150/\#151). Lacks sub-second resolution for burst micro-analysis.'  
      });  
      totalScore \+= 5;  
    } else {  
      checks.push({  
        id: 'timestamp\_precision',  
        name: 'High-Precision 64-bit Millisecond Timestamps',  
        score: 2,  
        maxScore: 10,  
        status: 'FAIL',  
        details: 'Legacy sysUpTime delta timestamps (IE \#21/\#22). Does not provide absolute wall-clock UTC timestamps without collector post-math.'  
      });  
      totalScore \+= 2;  
    }

    // 5\. 64-bit High-Capacity Volume Counters (10 pts)  
    const octetCounter \= fields.find(f \=\> f.id \=== 1);  
    const packetCounter \= fields.find(f \=\> f.id \=== 2);  
    const is64BitOctet \= octetCounter && (octetCounter.length \=== 8);  
    const is64BitPacket \= packetCounter && (packetCounter.length \=== 8);  
    if (is64BitOctet && is64BitPacket) {  
      checks.push({  
        id: 'high\_capacity\_counters',  
        name: '64-Bit High-Capacity Volume Counters',  
        score: 10,  
        maxScore: 10,  
        status: 'PASS',  
        details: '64-bit octet (\#1) and packet (\#2) counters configured. Guarantees zero integer counter wrapping on 100G/400G spine links.'  
      });  
      totalScore \+= 10;  
    } else if (octetCounter || packetCounter) {  
      checks.push({  
        id: 'high\_capacity\_counters',  
        name: '64-Bit High-Capacity Volume Counters',  
        score: 2,  
        maxScore: 10,  
        status: 'FAIL',  
        details: '32-bit counters detected. High risk of 32-bit counter rollover (every \~34 seconds at 1Gbps, \<1 sec at 100Gbps) leading to distorted bandwidth metrics.'  
      });  
      totalScore \+= 2;  
    } else {  
      checks.push({  
        id: 'high\_capacity\_counters',  
        name: '64-Bit High-Capacity Volume Counters',  
        score: 0,  
        maxScore: 10,  
        status: 'FAIL',  
        details: 'No octet or packet counters defined in template.'  
      });  
    }

    // 6\. Strict IANA Information Element 5-Tuple Compliance (10 pts)  
    const hasSrcIp \= fields.some(f \=\> f.id \=== 8 || f.id \=== 27);  
    const hasDstIp \= fields.some(f \=\> f.id \=== 12 || f.id \=== 28);  
    const hasProto \= fields.some(f \=\> f.id \=== 4);  
    const hasSrcPort \= fields.some(f \=\> f.id \=== 7);  
    const hasDstPort \= fields.some(f \=\> f.id \=== 11);  
    if (hasSrcIp && hasDstIp && hasProto && hasSrcPort && hasDstPort) {  
      checks.push({  
        id: 'five\_tuple\_compliance',  
        name: 'Complete 5-Tuple Network Flow Identification',  
        score: 10,  
        maxScore: 10,  
        status: 'PASS',  
        details: 'Full IANA 5-tuple (Src IP, Dst IP, Protocol, Src Port, Dst Port) present. Guarantees standard SIEM network mapping.'  
      });  
      totalScore \+= 10;  
    } else {  
      checks.push({  
        id: 'five\_tuple\_compliance',  
        name: 'Complete 5-Tuple Network Flow Identification',  
        score: 3,  
        maxScore: 10,  
        status: 'FAIL',  
        details: 'Incomplete 5-tuple keys. Missing critical flow routing or transport port attributes.'  
      });  
      totalScore \+= 3;  
    }

    // 7\. Sampling Interval Attribution & Option Template Export (10 pts)  
    const samplingEnabled \= \!\!cfg.samplingRate && parseInt(cfg.samplingRate, 10\) \> 1;  
    const optionTemplateEnabled \= \!\!cfg.optionTemplateEnabled;  
    if (samplingEnabled && optionTemplateEnabled) {  
      checks.push({  
        id: 'sampling\_options',  
        name: 'Sampling Rate Attribution (RFC 7011 Option Template)',  
        score: 10,  
        maxScore: 10,  
        status: 'PASS',  
        details: \`Sampling rate 1:\${cfg.samplingRate} configured with Option Template FlowSet export. Collectors will automatically scale traffic metrics.\`  
      });  
      totalScore \+= 10;  
    } else if (\!samplingEnabled) {  
      checks.push({  
        id: 'sampling\_options',  
        name: 'Sampling Rate Attribution (RFC 7011 Option Template)',  
        score: 10,  
        maxScore: 10,  
        status: 'PASS',  
        details: '1:1 full unsampled flow accounting. High fidelity for campus edge & datacenter core.'  
      });  
      totalScore \+= 10;  
    } else {  
      checks.push({  
        id: 'sampling\_options',  
        name: 'Sampling Rate Attribution (RFC 7011 Option Template)',  
        score: 2,  
        maxScore: 10,  
        status: 'FAIL',  
        details: \`Sampling rate 1:\${cfg.samplingRate} active without Option Template export. Downstream SIEM dashboards will underreport traffic volume by \${cfg.samplingRate}x.\`  
      });  
      totalScore \+= 2;  
    }

    // 8\. Bidirectional Interface Attribution (10 pts)  
    const hasIngress \= fields.some(f \=\> f.id \=== 10);  
    const hasEgress \= fields.some(f \=\> f.id \=== 14);  
    if (hasIngress && hasEgress) {  
      checks.push({  
        id: 'interface\_attribution',  
        name: 'Bidirectional SNMP Interface Index Attribution',  
        score: 10,  
        maxScore: 10,  
        status: 'PASS',  
        details: 'Both ingressInterface (\#10) and egressInterface (\#14) captured. Enables precise hop-by-hop path tracing.'  
      });  
      totalScore \+= 10;  
    } else if (hasIngress || hasEgress) {  
      checks.push({  
        id: 'interface\_attribution',  
        name: 'Bidirectional SNMP Interface Index Attribution',  
        score: 5,  
        maxScore: 10,  
        status: 'WARN',  
        details: 'Only unidirectional interface index exported. Ingress or egress path visibility is lost.'  
      });  
      totalScore \+= 5;  
    } else {  
      checks.push({  
        id: 'interface\_attribution',  
        name: 'Bidirectional SNMP Interface Index Attribution',  
        score: 0,  
        maxScore: 10,  
        status: 'FAIL',  
        details: 'Zero interface indices captured. Network flow records cannot be associated with physical switch ports.'  
      });  
    }

    // 9\. Redundant Collector & Failover Spooling (5 pts)  
    const hasSecondaryCollector \= \!\!cfg.secondaryCollectorHost;  
    if (hasSecondaryCollector) {  
      checks.push({  
        id: 'collector\_resilience',  
        name: 'Collector High-Availability & Redundant Export',  
        score: 5,  
        maxScore: 5,  
        status: 'PASS',  
        details: \`Redundant secondary collector configured (\${cfg.secondaryCollectorHost}). Prevents single point of failure.\`  
      });  
      totalScore \+= 5;  
    } else {  
      checks.push({  
        id: 'collector\_resilience',  
        name: 'Collector High-Availability & Redundant Export',  
        score: 2,  
        maxScore: 5,  
        status: 'WARN',  
        details: 'Single collector target configured. Outages on receiver host will cause immediate telemetry loss.'  
      });  
      totalScore \+= 2;  
    }

    // 10\. Flow Table Aging & Resource Protection (5 pts)  
    const activeTimeout \= parseInt(cfg.activeTimeoutSeconds || 60, 10);  
    const inactiveTimeout \= parseInt(cfg.inactiveTimeoutSeconds || 15, 10);  
    if (activeTimeout \<= 60 && inactiveTimeout \<= 15\) {  
      checks.push({  
        id: 'flow\_cache\_aging',  
        name: 'Flow Cache Aging & DoS Table Protection',  
        score: 5,  
        maxScore: 5,  
        status: 'PASS',  
        details: \`Optimal flow cache timeouts (Active: \${activeTimeout}s, Inactive: \${inactiveTimeout}s). Prevents router memory exhaustion during port scans.\`  
      });  
      totalScore \+= 5;  
    } else {  
      checks.push({  
        id: 'flow\_cache\_aging',  
        name: 'Flow Cache Aging & DoS Table Protection',  
        score: 1,  
        maxScore: 5,  
        status: 'WARN',  
        details: \`Suboptimal flow cache timeouts (Active: \${activeTimeout}s, Inactive: \${inactiveTimeout}s). May cause flow table memory exhaustion under attack.\`  
      });  
      totalScore \+= 1;  
    }

    // Compute Overall Grade  
    let grade \= 'F';  
    if (totalScore \>= 95\) grade \= 'A+';  
    else if (totalScore \>= 90\) grade \= 'A';  
    else if (totalScore \>= 80\) grade \= 'B';  
    else if (totalScore \>= 70\) grade \= 'C';  
    else if (totalScore \>= 60\) grade \= 'D';

    return {  
      score: totalScore,  
      maxScore: maxScore,  
      percentage: Math.round((totalScore / maxScore) \* 100),  
      grade: grade,  
      checks: checks,  
      passedCount: checks.filter(c \=\> c.status \=== 'PASS').length,  
      warnCount: checks.filter(c \=\> c.status \=== 'WARN').length,  
      failCount: checks.filter(c \=\> c.status \=== 'FAIL').length  
    };  
  }

  return {  
    auditFlowConfiguration  
  };  
}));  
