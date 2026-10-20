/\*\*  
 \* NetFlowIPFIXForge Pro \- Application State Orchestrator & UI Controller  
 \*/

(function () {  
  'use strict';

  const PRESETS \= {  
    'enterprise-zerotrust-ipfix-dtls': {  
      name: "Enterprise Zero-Trust RFC 7011 IPFIX / DTLS Telemetry",  
      protocol: "ipfix",  
      version: 10,  
      transport: "dtls",  
      port: 4740,  
      collectorHost: "flow-collector-01.corp.internal",  
      secondaryCollectorHost: "flow-collector-02.corp.internal",  
      exporterSourceIp: "10.200.4.1",  
      exporterSourceInterface: "Loopback0",  
      observationDomainId: 10,  
      templateId: 256,  
      templateTimeoutSeconds: 60,  
      templateRatePackets: 1000,  
      activeTimeoutSeconds: 60,  
      inactiveTimeoutSeconds: 15,  
      samplingRate: 1,  
      optionTemplateEnabled: true,  
      fields: \[  
        { id: 8, length: 4 },  
        { id: 12, length: 4 },  
        { id: 7, length: 2 },  
        { id: 11, length: 2 },  
        { id: 4, length: 1 },  
        { id: 6, length: 2 },  
        { id: 10, length: 4 },  
        { id: 14, length: 4 },  
        { id: 1, length: 8 },  
        { id: 2, length: 8 },  
        { id: 152, length: 8 },  
        { id: 153, length: 8 }  
      \]  
    },  
    'cloud-vpc-highcapacity-flow': {  
      name: "Cloud VPC High-Capacity 100G Backbone Telemetry",  
      protocol: "ipfix",  
      version: 10,  
      transport: "tls",  
      port: 4740,  
      collectorHost: "flow-gateway.cloud.internal",  
      secondaryCollectorHost: "flow-gateway-backup.cloud.internal",  
      exporterSourceIp: "172.24.0.1",  
      exporterSourceInterface: "Loopback101",  
      observationDomainId: 101,  
      templateId: 256,  
      templateTimeoutSeconds: 60,  
      templateRatePackets: 1000,  
      activeTimeoutSeconds: 60,  
      inactiveTimeoutSeconds: 15,  
      samplingRate: 1000,  
      optionTemplateEnabled: true,  
      fields: \[  
        { id: 8, length: 4 },  
        { id: 12, length: 4 },  
        { id: 7, length: 2 },  
        { id: 11, length: 2 },  
        { id: 4, length: 1 },  
        { id: 6, length: 2 },  
        { id: 10, length: 4 },  
        { id: 14, length: 4 },  
        { id: 1, length: 8 },  
        { id: 2, length: 8 },  
        { id: 152, length: 8 },  
        { id: 153, length: 8 }  
      \]  
    },  
    'vulnerable-legacy-netflow-v5': {  
      name: "Vulnerable Legacy NetFlow (Cleartext UDP 2055 / 32-bit)",  
      protocol: "netflow-v9",  
      version: 9,  
      transport: "udp",  
      port: 2055,  
      collectorHost: "192.168.1.100",  
      secondaryCollectorHost: "",  
      exporterSourceIp: "",  
      exporterSourceInterface: "FastEthernet0/1",  
      observationDomainId: 0,  
      templateId: 256,  
      templateTimeoutSeconds: 1800,  
      templateRatePackets: 100000,  
      activeTimeoutSeconds: 1800,  
      inactiveTimeoutSeconds: 60,  
      samplingRate: 1000,  
      optionTemplateEnabled: false,  
      fields: \[  
        { id: 8, length: 4 },  
        { id: 12, length: 4 },  
        { id: 7, length: 2 },  
        { id: 11, length: 2 },  
        { id: 4, length: 1 },  
        { id: 10, length: 4 },  
        { id: 1, length: 4 },  
        { id: 2, length: 4 },  
        { id: 21, length: 4 },  
        { id: 22, length: 4 }  
      \]  
    }  
  };

  let currentFields \= \[\];  
  let activeVendorTab \= 'tab-cisco';

  // DOM Elements  
  const elPresetSelect \= document.getElementById('preset-select');  
  const elBtnResetPreset \= document.getElementById('btn-reset-preset');  
  const elBtnExportJson \= document.getElementById('btn-export-json');

  const elFlowProtocol \= document.getElementById('flow-protocol');  
  const elFlowTransport \= document.getElementById('flow-transport');  
  const elObsDomainId \= document.getElementById('obs-domain-id');  
  const elTemplateId \= document.getElementById('template-id-input');  
  const elExporterSourceIp \= document.getElementById('exporter-source-ip');  
  const elPrimaryCollector \= document.getElementById('primary-collector-host');  
  const elSecondaryCollector \= document.getElementById('secondary-collector-host');

  const elHeaderSizeDisplay \= document.getElementById('header-size-display');  
  const elRecordSizeDisplay \= document.getElementById('record-size-display');  
  const elFieldCountDisplay \= document.getElementById('field-count-display');  
  const elIeFieldsContainer \= document.getElementById('ie-fields-container');

  const elTemplateTimeout \= document.getElementById('template-timeout');  
  const elSamplingRate \= document.getElementById('sampling-rate');  
  const elChkOptionTemplate \= document.getElementById('chk-option-template');  
  const elChkFlowAging \= document.getElementById('chk-flow-aging');

  const elScorecardGrade \= document.getElementById('scorecard-grade');  
  const elScoreFill \= document.getElementById('score-fill');  
  const elScorePoints \= document.getElementById('score-points');  
  const elScorePercentage \= document.getElementById('score-percentage');  
  const elPassedCount \= document.getElementById('passed-count');  
  const elWarnCount \= document.getElementById('warn-count');  
  const elFailCount \= document.getElementById('fail-count');  
  const elRubricChecklist \= document.getElementById('rubric-checklist');

  const elTotalPacketSize \= document.getElementById('total-packet-size');  
  const elHexDumpCode \= document.getElementById('hex-dump-code');  
  const elBtnCopyHexDump \= document.getElementById('btn-copy-hexdump');

  const elVendorSynthesizerCode \= document.getElementById('vendor-synthesizer-code');  
  const elBtnCopyConfig \= document.getElementById('btn-copy-config');  
  const elBtnDownloadConfig \= document.getElementById('btn-download-config');

  function renderIEFields() {  
    elIeFieldsContainer.innerHTML \= '';  
    currentFields.forEach((f, idx) \=\> {  
      const ie \= NetFlowEngine.getInformationElement(f.id);  
      const item \= document.createElement('div');  
      item.className \= 'ie-item';  
      item.innerHTML \= \`  
        \<div class="ie-item-title"\>  
          \<span class="ie-badge"\>\#\${f.id}\</span\>  
          \<strong\>\${ie ? ie.name : 'IE\_' \+ f.id}\</strong\>  
          \<span class="help-text"\>(\${ie ? ie.type : 'octetArray'})\</span\>  
        \</div\>  
        \<div class="ie-item-actions"\>  
          \<select class="select-input font-mono ie-length-select" data-idx="\${idx}" style="width: auto; padding: 2px 6px;"\>  
            \<option value="1" \${f.length \=== 1 ? 'selected' : ''}\>1 byte\</option\>  
            \<option value="2" \${f.length \=== 2 ? 'selected' : ''}\>2 bytes\</option\>  
            \<option value="4" \${f.length \=== 4 ? 'selected' : ''}\>4 bytes\</option\>  
            \<option value="8" \${f.length \=== 8 ? 'selected' : ''}\>8 bytes\</option\>  
            \<option value="16" \${f.length \=== 16 ? 'selected' : ''}\>16 bytes\</option\>  
          \</select\>  
          \<button class="btn btn-sm btn-secondary ie-remove-btn" data-idx="\${idx}"\>\&times;\</button\>  
        \</div\>  
      \`;  
      elIeFieldsContainer.appendChild(item);  
    });

    // Attach listeners  
    document.querySelectorAll('.ie-length-select').forEach(sel \=\> {  
      sel.addEventListener('change', (e) \=\> {  
        const idx \= parseInt(e.target.getAttribute('data-idx'), 10);  
        currentFields\[idx\].length \= parseInt(e.target.value, 10);  
        updateUI();  
      });  
    });

    document.querySelectorAll('.ie-remove-btn').forEach(btn \=\> {  
      btn.addEventListener('click', (e) \=\> {  
        const idx \= parseInt(e.target.getAttribute('data-idx'), 10);  
        currentFields.splice(idx, 1);  
        renderIEFields();  
        updateUI();  
      });  
    });

    const recordSize \= NetFlowEngine.calculateDataRecordSize(currentFields);  
    elRecordSizeDisplay.textContent \= \`\${recordSize} bytes\`;  
    elFieldCountDisplay.textContent \= currentFields.length;  
  }

  function getCurrentConfig() {  
    const isIpfix \= elFlowProtocol.value \=== 'ipfix';  
    return {  
      protocol: elFlowProtocol.value,  
      version: isIpfix ? 10 : 9,  
      transport: elFlowTransport.value,  
      port: elFlowTransport.value \=== 'udp' ? 2055 : 4740,  
      observationDomainId: parseInt(elObsDomainId.value, 10\) || 0,  
      templateId: parseInt(elTemplateId.value, 10\) || 256,  
      exporterSourceIp: elExporterSourceIp.value.trim(),  
      collectorHost: elPrimaryCollector.value.trim(),  
      secondaryCollectorHost: elSecondaryCollector.value.trim(),  
      templateTimeoutSeconds: parseInt(elTemplateTimeout.value, 10\) || 60,  
      samplingRate: parseInt(elSamplingRate.value, 10\) || 1,  
      optionTemplateEnabled: elChkOptionTemplate.checked,  
      activeTimeoutSeconds: elChkFlowAging.checked ? 60 : 1800,  
      inactiveTimeoutSeconds: elChkFlowAging.checked ? 15 : 60,  
      fields: currentFields  
    };  
  }

  function applyConfig(cfg) {  
    if (\!cfg) return;  
    elFlowProtocol.value \= cfg.protocol || 'ipfix';  
    elFlowTransport.value \= cfg.transport || 'dtls';  
    elObsDomainId.value \= cfg.observationDomainId \!== undefined ? cfg.observationDomainId : 10;  
    elTemplateId.value \= cfg.templateId || 256;  
    elExporterSourceIp.value \= cfg.exporterSourceIp || '10.200.4.1';  
    elPrimaryCollector.value \= cfg.collectorHost || 'flow-collector-01.corp.internal';  
    elSecondaryCollector.value \= cfg.secondaryCollectorHost || '';  
    elTemplateTimeout.value \= cfg.templateTimeoutSeconds || 60;  
    elSamplingRate.value \= cfg.samplingRate || 1;  
    elChkOptionTemplate.checked \= \!\!cfg.optionTemplateEnabled;  
    elChkFlowAging.checked \= (cfg.activeTimeoutSeconds || 60\) \<= 60;

    currentFields \= (cfg.fields || \[\]).map(f \=\> ({ id: f.id, length: f.length || 4 }));  
    renderIEFields();  
    updateUI();  
  }

  function updateUI() {  
    const cfg \= getCurrentConfig();  
    elHeaderSizeDisplay.textContent \= cfg.version \=== 10 ? '16 bytes (IPFIX)' : '20 bytes (NetFlow v9)';

    // 1\. Audit  
    const audit \= NetFlowSecurityAuditor.auditFlowConfiguration(cfg);  
    elScorecardGrade.textContent \= audit.grade;  
    elScorecardGrade.className \= 'grade-badge ' \+ (audit.grade \=== 'A+' || audit.grade \=== 'A' ? 'grade-a' : (audit.grade \=== 'B' || audit.grade \=== 'C' ? 'grade-b' : 'grade-f'));  
    elScoreFill.style.width \= \`\${audit.percentage}%\`;  
    elScorePoints.textContent \= audit.score;  
    elScorePercentage.textContent \= \`\${audit.percentage}%\`;  
    elPassedCount.textContent \= audit.passedCount;  
    elWarnCount.textContent \= audit.warnCount;  
    elFailCount.textContent \= audit.failCount;

    // Render Checklist  
    elRubricChecklist.innerHTML \= '';  
    audit.checks.forEach(check \=\> {  
      const item \= document.createElement('div');  
      item.className \= 'rubric-item';  
      const statusClass \= check.status \=== 'PASS' ? 'status-pass' : (check.status \=== 'WARN' ? 'status-warn' : 'status-fail');  
      const icon \= check.status \=== 'PASS' ? '✅' : (check.status \=== 'WARN' ? '⚠️' : '❌');  
      item.innerHTML \= \`  
        \<div\>  
          \<span class="rubric-status \${statusClass}"\>\${icon} \${check.status}\</span\>  
          \<strong\>\${check.name}\</strong\> (\${check.score}/\${check.maxScore} pts)  
          \<div class="help-text"\>\${check.details}\</div\>  
        \</div\>  
      \`;  
      elRubricChecklist.appendChild(item);  
    });

    // 2\. Build Wireframe  
    const pkt \= NetFlowEngine.buildFlowPacket(cfg);  
    elTotalPacketSize.textContent \= \`\${pkt.totalLength} bytes\`;  
    elHexDumpCode.textContent \= pkt.hexDump;

    // 3\. Synthesize  
    updateSynthesizerPreview(cfg);  
  }

  function updateSynthesizerPreview(cfg) {  
    let output \= '';  
    if (activeVendorTab \=== 'tab-cisco') {  
      output \= NetFlowConfigSynthesizer.synthesizeCiscoFNF(cfg);  
    } else if (activeVendorTab \=== 'tab-juniper') {  
      output \= NetFlowConfigSynthesizer.synthesizeJuniperJunos(cfg);  
    } else if (activeVendorTab \=== 'tab-pmacct') {  
      output \= NetFlowConfigSynthesizer.synthesizePmacct(cfg);  
    } else if (activeVendorTab \=== 'tab-logstash') {  
      output \= NetFlowConfigSynthesizer.synthesizeLogstash(cfg);  
    } else if (activeVendorTab \=== 'tab-ntopng') {  
      output \= NetFlowConfigSynthesizer.synthesizeNtopng(cfg);  
    } else if (activeVendorTab \=== 'tab-python') {  
      output \= NetFlowConfigSynthesizer.synthesizePythonClient(cfg);  
    }  
    elVendorSynthesizerCode.textContent \= output;  
  }

  function setupEventHandlers() {  
    const inputs \= \[  
      elFlowProtocol, elFlowTransport, elObsDomainId, elTemplateId,  
      elExporterSourceIp, elPrimaryCollector, elSecondaryCollector,  
      elTemplateTimeout, elSamplingRate, elChkOptionTemplate, elChkFlowAging  
    \];  
    inputs.forEach(el \=\> {  
      el.addEventListener('input', updateUI);  
      el.addEventListener('change', updateUI);  
    });

    // Quick add buttons  
    document.getElementById('btn-add-standard-ie').addEventListener('click', () \=\> {  
      const std \= \[8, 12, 7, 11, 4\]; // SrcIP, DstIP, SrcPort, DstPort, Proto  
      std.forEach(id \=\> {  
        if (\!currentFields.some(f \=\> f.id \=== id)) {  
          const ie \= NetFlowEngine.getInformationElement(id);  
          currentFields.push({ id, length: ie.defaultLength });  
        }  
      });  
      renderIEFields();  
      updateUI();  
    });

    document.getElementById('btn-add-64bit-counters').addEventListener('click', () \=\> {  
      \[1, 2\].forEach(id \=\> { // octetDeltaCount, packetDeltaCount  
        const existing \= currentFields.find(f \=\> f.id \=== id);  
        if (existing) existing.length \= 8;  
        else currentFields.push({ id, length: 8 });  
      });  
      renderIEFields();  
      updateUI();  
    });

    document.getElementById('btn-add-ms-timestamps').addEventListener('click', () \=\> {  
      \[152, 153\].forEach(id \=\> { // flowStartMilliseconds, flowEndMilliseconds  
        if (\!currentFields.some(f \=\> f.id \=== id)) currentFields.push({ id, length: 8 });  
      });  
      renderIEFields();  
      updateUI();  
    });

    document.getElementById('btn-add-interfaces').addEventListener('click', () \=\> {  
      \[10, 14\].forEach(id \=\> { // ingressInterface, egressInterface  
        if (\!currentFields.some(f \=\> f.id \=== id)) currentFields.push({ id, length: 4 });  
      });  
      renderIEFields();  
      updateUI();  
    });

    // Preset selector  
    elPresetSelect.addEventListener('change', () \=\> {  
      const presetKey \= elPresetSelect.value;  
      if (PRESETS\[presetKey\]) applyConfig(PRESETS\[presetKey\]);  
    });

    elBtnResetPreset.addEventListener('click', () \=\> {  
      const presetKey \= elPresetSelect.value;  
      if (PRESETS\[presetKey\]) applyConfig(PRESETS\[presetKey\]);  
    });

    // Export JSON  
    elBtnExportJson.addEventListener('click', () \=\> {  
      const cfg \= getCurrentConfig();  
      const blob \= new Blob(\[JSON.stringify(cfg, null, 2)\], { type: 'application/json' });  
      const url \= URL.createObjectURL(blob);  
      const a \= document.createElement('a');  
      a.href \= url;  
      a.download \= \`flow-template-\${cfg.protocol}-t\${cfg.templateId}.json\`;  
      a.click();  
      URL.revokeObjectURL(url);  
    });

    // Vendor Tabs  
    const vendorTabBtns \= document.querySelectorAll('\#vendor-tabs .tab-btn');  
    vendorTabBtns.forEach(btn \=\> {  
      btn.addEventListener('click', () \=\> {  
        vendorTabBtns.forEach(b \=\> b.classList.remove('active'));  
        btn.classList.add('active');  
        activeVendorTab \= btn.getAttribute('data-tab');  
        updateSynthesizerPreview(getCurrentConfig());  
      });  
    });

    // Copy buttons  
    elBtnCopyHexDump.addEventListener('click', () \=\> {  
      navigator.clipboard.writeText(elHexDumpCode.textContent).then(() \=\> {  
        const orig \= elBtnCopyHexDump.textContent;  
        elBtnCopyHexDump.textContent \= 'Copied\!';  
        setTimeout(() \=\> elBtnCopyHexDump.textContent \= orig, 1500);  
      });  
    });

    elBtnCopyConfig.addEventListener('click', () \=\> {  
      navigator.clipboard.writeText(elVendorSynthesizerCode.textContent).then(() \=\> {  
        const orig \= elBtnCopyConfig.textContent;  
        elBtnCopyConfig.textContent \= 'Copied\!';  
        setTimeout(() \=\> elBtnCopyConfig.textContent \= orig, 1500);  
      });  
    });

    // Download Config  
    elBtnDownloadConfig.addEventListener('click', () \=\> {  
      const code \= elVendorSynthesizerCode.textContent;  
      let filename \= 'flow-config.txt';  
      if (activeVendorTab \=== 'tab-cisco') filename \= 'cisco-fnf.cfg';  
      else if (activeVendorTab \=== 'tab-juniper') filename \= 'juniper-ipfix.set';  
      else if (activeVendorTab \=== 'tab-pmacct') filename \= 'nfacctd.conf';  
      else if (activeVendorTab \=== 'tab-logstash') filename \= 'logstash-netflow.conf';  
      else if (activeVendorTab \=== 'tab-ntopng') filename \= 'nprobe.conf';  
      else if (activeVendorTab \=== 'tab-python') filename \= 'test\_ipfix\_sender.py';

      const blob \= new Blob(\[code\], { type: 'text/plain' });  
      const url \= URL.createObjectURL(blob);  
      const a \= document.createElement('a');  
      a.href \= url;  
      a.download \= filename;  
      a.click();  
      URL.revokeObjectURL(url);  
    });  
  }

  // Init  
  setupEventHandlers();  
  applyConfig(PRESETS\['enterprise-zerotrust-ipfix-dtls'\]);  
})();  
