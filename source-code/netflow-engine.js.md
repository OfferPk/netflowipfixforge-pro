/\*\*  
 \* NetFlowIPFIXForge Pro \- Protocol & Template Modeling Engine  
 \* RFC 7011 (IPFIX Protocol Specification), RFC 7012 (Information Model), RFC 3954 (Cisco NetFlow v9)  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.NetFlowEngine \= factory();  
  }  
}(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  // IANA Standard Information Elements (IEs)  
  const IANA\_INFORMATION\_ELEMENTS \= {  
    1: { id: 1, name: 'octetDeltaCount', type: 'unsigned64', defaultLength: 8, desc: 'Number of octets since the previous report' },  
    2: { id: 2, name: 'packetDeltaCount', type: 'unsigned64', defaultLength: 8, desc: 'Number of incoming packets since previous report' },  
    4: { id: 4, name: 'protocolIdentifier', type: 'unsigned8', defaultLength: 1, desc: 'IPv4 protocol or IPv6 Next Header (TCP=6, UDP=17, ICMP=1)' },  
    5: { id: 5, name: 'ipClassOfService', type: 'unsigned8', defaultLength: 1, desc: 'Type of Service / Traffic Class byte' },  
    6: { id: 6, name: 'tcpControlBits', type: 'unsigned16', defaultLength: 2, desc: 'Cumulative TCP control flags (SYN, ACK, FIN, RST, PSH, URG)' },  
    7: { id: 7, name: 'sourceTransportPort', type: 'unsigned16', defaultLength: 2, desc: 'Source port identifier in transport layer' },  
    8: { id: 8, name: 'sourceIPv4Address', type: 'ipv4Address', defaultLength: 4, desc: 'IPv4 source address in IP header' },  
    9: { id: 9, name: 'sourceIPv4PrefixLength', type: 'unsigned8', defaultLength: 1, desc: 'IPv4 source subnet prefix mask length' },  
    10: { id: 10, name: 'ingressInterface', type: 'unsigned32', defaultLength: 4, desc: 'Index of SNMP ifIndex where flow entered device' },  
    11: { id: 11, name: 'destinationTransportPort', type: 'unsigned16', defaultLength: 2, desc: 'Destination port identifier in transport layer' },  
    12: { id: 12, name: 'destinationIPv4Address', type: 'ipv4Address', defaultLength: 4, desc: 'IPv4 destination address in IP header' },  
    13: { id: 13, name: 'destinationIPv4PrefixLength', type: 'unsigned8', defaultLength: 1, desc: 'IPv4 destination subnet prefix mask length' },  
    14: { id: 14, name: 'egressInterface', type: 'unsigned32', defaultLength: 4, desc: 'Index of SNMP ifIndex where flow left device' },  
    15: { id: 15, name: 'ipNextHopIPv4Address', type: 'ipv4Address', defaultLength: 4, desc: 'IPv4 address of the next-hop router' },  
    16: { id: 16, name: 'bgpSourceAsNumber', type: 'unsigned32', defaultLength: 4, desc: 'BGP Autonomous System number of the source' },  
    17: { id: 17, name: 'bgpDestinationAsNumber', type: 'unsigned32', defaultLength: 4, desc: 'BGP Autonomous System number of the destination' },  
    21: { id: 21, name: 'flowEndSysUpTime', type: 'unsigned32', defaultLength: 4, desc: 'sysUpTime in ms when the last packet was observed' },  
    22: { id: 22, name: 'flowStartSysUpTime', type: 'unsigned32', defaultLength: 4, desc: 'sysUpTime in ms when the first packet was observed' },  
    27: { id: 27, name: 'sourceIPv6Address', type: 'ipv6Address', defaultLength: 16, desc: 'IPv6 source address in IP header' },  
    28: { id: 28, name: 'destinationIPv6Address', type: 'ipv6Address', defaultLength: 16, desc: 'IPv6 destination address in IP header' },  
    56: { id: 56, name: 'sourceMacAddress', type: 'macAddress', defaultLength: 6, desc: 'IEEE 802 source MAC address' },  
    80: { id: 80, name: 'destinationMacAddress', type: 'macAddress', defaultLength: 6, desc: 'IEEE 802 destination MAC address' },  
    136: { id: 136, name: 'flowEndReason', type: 'unsigned8', defaultLength: 1, desc: 'Reason why flow was terminated (idle, active, end-of-flow)' },  
    148: { id: 148, name: 'flowId', type: 'unsigned64', defaultLength: 8, desc: 'Locally unique 64-bit Flow Identifier' },  
    150: { id: 150, name: 'flowStartSeconds', type: 'dateTimeSeconds', defaultLength: 4, desc: 'Absolute start time in Unix epoch seconds' },  
    151: { id: 151, name: 'flowEndSeconds', type: 'dateTimeSeconds', defaultLength: 4, desc: 'Absolute end time in Unix epoch seconds' },  
    152: { id: 152, name: 'flowStartMilliseconds', type: 'dateTimeMilliseconds', defaultLength: 8, desc: 'Absolute start timestamp in epoch ms' },  
    153: { id: 153, name: 'flowEndMilliseconds', type: 'dateTimeMilliseconds', defaultLength: 8, desc: 'Absolute end timestamp in epoch ms' },  
    225: { id: 225, name: 'postNATSourceIPv4Address', type: 'ipv4Address', defaultLength: 4, desc: 'Post-NAT IPv4 translated source address' },  
    226: { id: 226, name: 'postNATDestinationIPv4Address', type: 'ipv4Address', defaultLength: 4, desc: 'Post-NAT IPv4 translated destination address' },  
    227: { id: 227, name: 'postNAPTSourceTransportPort', type: 'unsigned16', defaultLength: 2, desc: 'Post-NAPT translated source port' },  
    228: { id: 228, name: 'postNAPTDestinationTransportPort', type: 'unsigned16', defaultLength: 2, desc: 'Post-NAPT translated destination port' }  
  };

  /\*\*  
   \* Looks up an IE by numeric ID or element name  
   \*/  
  function getInformationElement(idOrName) {  
    if (typeof idOrName \=== 'number' || \!isNaN(parseInt(idOrName, 10))) {  
      const id \= parseInt(idOrName, 10);  
      return IANA\_INFORMATION\_ELEMENTS\[id\] || { id: id, name: \`ie\_\${id}\`, type: 'octetArray', defaultLength: 4, desc: 'Vendor or Unknown IE' };  
    }  
    const name \= String(idOrName).toLowerCase();  
    for (const ie of Object.values(IANA\_INFORMATION\_ELEMENTS)) {  
      if (ie.name.toLowerCase() \=== name) return ie;  
    }  
    return null;  
  }

  /\*\*  
   \* Calculates the byte size of a single data record for a given template field list  
   \*/  
  function calculateDataRecordSize(fields) {  
    if (\!fields || \!Array.isArray(fields)) return 0;  
    return fields.reduce((acc, f) \=\> acc \+ (f.length || f.defaultLength || 4), 0);  
  }

  /\*\*  
   \* Builds an RFC 7011 IPFIX / Cisco NetFlow v9 Packet Specification and Wireframe  
   \*/  
  function buildFlowPacket(options) {  
    const opts \= options || {};  
    const protocolVersion \= parseInt(opts.version || 10, 10); // 10 \= IPFIX, 9 \= NetFlow v9  
    const templateId \= parseInt(opts.templateId || 256, 10);  
    const observationDomainId \= parseInt(opts.observationDomainId \!== undefined ? opts.observationDomainId : 1, 10);  
    const sequenceNumber \= parseInt(opts.sequenceNumber || 1001, 10);  
    const epochSeconds \= Math.floor((opts.timestamp ? new Date(opts.timestamp).getTime() : Date.now()) / 1000);  
    const sysUpTimeMs \= parseInt(opts.sysUpTimeMs || 8492010, 10);

    const fields \= opts.fields && opts.fields.length \> 0 ? opts.fields : \[  
      { id: 8, length: 4 },   // sourceIPv4Address  
      { id: 12, length: 4 },  // destinationIPv4Address  
      { id: 7, length: 2 },   // sourceTransportPort  
      { id: 11, length: 2 },  // destinationTransportPort  
      { id: 4, length: 1 },   // protocolIdentifier  
      { id: 6, length: 2 },   // tcpControlBits  
      { id: 10, length: 4 },  // ingressInterface  
      { id: 14, length: 4 },  // egressInterface  
      { id: 1, length: 8 },   // octetDeltaCount (64-bit)  
      { id: 2, length: 8 },   // packetDeltaCount (64-bit)  
      { id: 152, length: 8 }, // flowStartMilliseconds (64-bit)  
      { id: 153, length: 8 }  // flowEndMilliseconds (64-bit)  
    \];

    // Compute FlowSets  
    const templateSetId \= protocolVersion \=== 10 ? 2 : 0;  
    const templateFieldCount \= fields.length;  
    // Template Record: Template ID (2 bytes) \+ Field Count (2 bytes) \+ (Field Type (2) \+ Field Length (2)) \* N  
    const templateRecordLength \= 4 \+ (templateFieldCount \* 4);  
    // Template FlowSet: Set ID (2 bytes) \+ Length (2 bytes) \+ Template Record  
    const templateFlowSetLength \= 4 \+ templateRecordLength;

    // Data FlowSet  
    const dataRecordLength \= calculateDataRecordSize(fields);  
    const numDataRecords \= parseInt(opts.numRecords || 1, 10);  
    const rawDataLength \= numDataRecords \* dataRecordLength;  
    // Padding to 4-byte boundary  
    const padding \= (4 \- (rawDataLength % 4)) % 4;  
    const dataFlowSetLength \= 4 \+ rawDataLength \+ padding;

    // Total Packet Length  
    const headerLength \= protocolVersion \=== 10 ? 16 : 20;  
    const totalPacketLength \= headerLength \+ templateFlowSetLength \+ dataFlowSetLength;

    // Build Breakdown  
    const breakdown \= {  
      protocol: protocolVersion \=== 10 ? 'IPFIX (RFC 7011 / Version 10)' : 'Cisco NetFlow v9 (RFC 3954)',  
      version: protocolVersion,  
      headerLength,  
      totalLength: totalPacketLength,  
      epochSeconds,  
      timestampIso: new Date(epochSeconds \* 1000).toISOString(),  
      sysUpTimeMs,  
      sequenceNumber,  
      observationDomainId,  
      templateFlowSet: {  
        setId: templateSetId,  
        length: templateFlowSetLength,  
        templateId,  
        fieldCount: templateFieldCount,  
        fields: fields.map(f \=\> {  
          const ie \= getInformationElement(f.id);  
          return {  
            id: f.id,  
            name: ie ? ie.name : \`custom\_ie\_\${f.id}\`,  
            length: f.length || ie.defaultLength,  
            type: ie ? ie.type : 'octetArray',  
            desc: ie ? ie.desc : 'Custom or Vendor IE'  
          };  
        })  
      },  
      dataFlowSet: {  
        setId: templateId,  
        length: dataFlowSetLength,  
        recordLength: dataRecordLength,  
        numRecords: numDataRecords,  
        padding  
      }  
    };

    // Synthesize Hex Stream & Visual Byte Layout  
    const hexParts \= \[\];  
    if (protocolVersion \=== 10\) {  
      // IPFIX Header: Ver(2), Len(2), ExportTime(4), Seq(4), ObsDomain(4)  
      hexParts.push('00 0a');  
      hexParts.push(totalPacketLength.toString(16).padStart(4, '0'));  
      hexParts.push(epochSeconds.toString(16).padStart(8, '0'));  
      hexParts.push(sequenceNumber.toString(16).padStart(8, '0'));  
      hexParts.push(observationDomainId.toString(16).padStart(8, '0'));  
    } else {  
      // NetFlow v9 Header: Ver(2), Count(2), sysUpTime(4), UnixSec(4), Seq(4), SourceID(4)  
      hexParts.push('00 09');  
      hexParts.push((numDataRecords \+ 1).toString(16).padStart(4, '0')); // 1 template \+ N data  
      hexParts.push(sysUpTimeMs.toString(16).padStart(8, '0'));  
      hexParts.push(epochSeconds.toString(16).padStart(8, '0'));  
      hexParts.push(sequenceNumber.toString(16).padStart(8, '0'));  
      hexParts.push(observationDomainId.toString(16).padStart(8, '0'));  
    }

    // Template FlowSet  
    hexParts.push(templateSetId.toString(16).padStart(4, '0'));  
    hexParts.push(templateFlowSetLength.toString(16).padStart(4, '0'));  
    hexParts.push(templateId.toString(16).padStart(4, '0'));  
    hexParts.push(templateFieldCount.toString(16).padStart(4, '0'));  
    fields.forEach(f \=\> {  
      hexParts.push(f.id.toString(16).padStart(4, '0'));  
      hexParts.push((f.length || 4).toString(16).padStart(4, '0'));  
    });

    // Data FlowSet  
    hexParts.push(templateId.toString(16).padStart(4, '0'));  
    hexParts.push(dataFlowSetLength.toString(16).padStart(4, '0'));

    // Simulated data record payload bytes  
    for (let r \= 0; r \< numDataRecords; r++) {  
      fields.forEach(f \=\> {  
        const len \= f.length || 4;  
        if (f.id \=== 8\) hexParts.push('0a c8 04 01'); // 10.200.4.1  
        else if (f.id \=== 12\) hexParts.push('c6 33 64 2c'); // 198.51.100.44  
        else if (f.id \=== 7\) hexParts.push('d0 00'); // 53248  
        else if (f.id \=== 11\) hexParts.push('01 bb'); // 443 (HTTPS)  
        else if (f.id \=== 4\) hexParts.push('06'); // TCP  
        else if (f.id \=== 6\) hexParts.push('00 12'); // SYN+ACK  
        else if (f.id \=== 10\) hexParts.push('00 00 00 02'); // ifIndex 2  
        else if (f.id \=== 14\) hexParts.push('00 00 00 04'); // ifIndex 4  
        else if (f.id \=== 1 && len \=== 8\) hexParts.push('00 00 00 01 2a 05 90 00'); // 4,999,942,144 bytes  
        else if (f.id \=== 2 && len \=== 8\) hexParts.push('00 00 00 00 00 34 a0 12'); // 3,448,850 packets  
        else if (f.id \=== 152 && len \=== 8\) hexParts.push('00 00 01 92 84 a0 21 00'); // ms start  
        else if (f.id \=== 153 && len \=== 8\) hexParts.push('00 00 01 92 84 b0 18 00'); // ms end  
        else {  
          hexParts.push('00 '.repeat(len).trim());  
        }  
      });  
    }

    if (padding \> 0\) {  
      hexParts.push('00 '.repeat(padding).trim());  
    }

    const hexString \= hexParts.join(' ').replace(/\\s+/g, ' ');  
    breakdown.hexDump \= formatHexDump(hexString);  
    breakdown.rawHex \= hexString;

    return breakdown;  
  }

  function formatHexDump(rawHex) {  
    const bytes \= rawHex.split(' ');  
    const lines \= \[\];  
    for (let i \= 0; i \< bytes.length; i \+= 16\) {  
      const chunk \= bytes.slice(i, i \+ 16);  
      const offset \= i.toString(16).padStart(4, '0');  
      const hexLine \= chunk.join(' ').padEnd(48, ' ');  
      const ascii \= chunk.map(b \=\> {  
        const val \= parseInt(b, 16);  
        return (val \>= 32 && val \<= 126\) ? String.fromCharCode(val) : '.';  
      }).join('');  
      lines.push(\`\${offset}:  \${hexLine}  |\${ascii}|\`);  
    }  
    return lines.join('\\n');  
  }

  return {  
    IANA\_INFORMATION\_ELEMENTS,  
    getInformationElement,  
    calculateDataRecordSize,  
    buildFlowPacket,  
    formatHexDump  
  };  
}));  
