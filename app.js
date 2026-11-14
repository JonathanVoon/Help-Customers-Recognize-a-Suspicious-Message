(function () {
  'use strict';

  const els = {
    checkerForm: document.getElementById('checkerForm'),
    regionSelect: document.getElementById('regionSelect'),
    phoneInput: document.getElementById('phoneInput'),
    messageInput: document.getElementById('messageInput'),
    fillExampleBtn: document.getElementById('fillExampleBtn'),
    clearBtn: document.getElementById('clearBtn'),
    emptyStatePanel: document.getElementById('emptyStatePanel'),
    activeResultsWrap: document.getElementById('activeResultsWrap'),
    statPhone: document.getElementById('statPhone'),
    statLineType: document.getElementById('statLineType'),
    statOrigin: document.getElementById('statOrigin'),
    statFormatStatus: document.getElementById('statFormatStatus'),
    messageDisplayBox: document.getElementById('messageDisplayBox'),
    msgSenderLabel: document.getElementById('msgSenderLabel'),
    riskScoreLabel: document.getElementById('riskScoreLabel'),
    messageDisplayBody: document.getElementById('messageDisplayBody'),
    footerAiSummary: document.getElementById('footerAiSummary'),
    verdictRectBadge: document.getElementById('verdictRectBadge'),
    verdictRectIcon: document.getElementById('verdictRectIcon'),
    verdictRectText: document.getElementById('verdictRectText'),
    connectedAlertBar: document.getElementById('connectedAlertBar'),
    alertBarIcon: document.getElementById('alertBarIcon'),
    alertBarText: document.getElementById('alertBarText'),
    warningList: document.getElementById('warningList'),
    safeStepsList: document.getElementById('safeStepsList')
  };

  function autoDetectRegion() {
    try {
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
      if (/Singapore/i.test(tz)) return 'SG';
      if (/Kuala_Lumpur|Kuching/i.test(tz)) return 'MY';
      if (/Hong_Kong/i.test(tz)) return 'HK';
      if (/London|Belfast/i.test(tz)) return 'UK';
      if (/Sydney|Melbourne|Brisbane|Perth|Adelaide/i.test(tz)) return 'AU';
      if (/America\/(New_York|Chicago|Denver|Los_Angeles|Toronto|Vancouver)/i.test(tz)) return 'US/CA';
    } catch (_) {}
    return 'AUTO';
  }

  function escapeText(s) {
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  function runCheck() {
    const phone = els.phoneInput.value.trim();
    const message = els.messageInput.value;
    const region = els.regionSelect.value || 'AUTO';
    const result = window.SafeCheckAI.analyzeMessage(message, phone, region);

    if (result.empty) {
      els.emptyStatePanel.style.display = 'block';
      els.activeResultsWrap.style.display = 'none';
      return;
    }

    els.emptyStatePanel.style.display = 'none';
    els.activeResultsWrap.style.display = 'block';

    const prof = result.numberProfile;
    els.statPhone.textContent = prof.display;
    els.statLineType.textContent = prof.lineType;
    els.statOrigin.textContent = prof.origin;
    els.statFormatStatus.textContent = prof.formatStatus;

    if (result.verdict === 'suspicious') {
      els.statFormatStatus.style.color = '#dc2626';
    } else if (result.verdict === 'caution') {
      els.statFormatStatus.style.color = '#d97706';
    } else {
      els.statFormatStatus.style.color = '#059669';
    }

    els.msgSenderLabel.textContent = phone ? `Contact Number / Sender: ${phone}` : 'Message Content Inspection';
    els.riskScoreLabel.textContent = `AI Risk Score: ${result.riskScore}/100`;

    if (message.trim()) {
      els.messageDisplayBody.innerHTML = result.highlightedHtml;
    } else {
      els.messageDisplayBody.innerHTML = `<em>Checking contact number <strong>${escapeText(phone)}</strong>. Paste the message you received from this number in Step 2 above to scan links and wording.</em>`;
    }

    if (result.verdict === 'suspicious') {
      els.messageDisplayBox.className = 'message-display-box is-suspicious';
      els.verdictRectBadge.className = 'verdict-rect-badge verdict-suspicious';
      els.verdictRectIcon.textContent = '✕';
      els.verdictRectText.textContent = 'Suspicious';
      els.footerAiSummary.textContent = `AI flagged ${result.warningSigns.length} warning sign${result.warningSigns.length === 1 ? '' : 's'} on this number / message`;

      els.connectedAlertBar.className = 'connected-alert-bar verdict-suspicious';
      els.alertBarIcon.textContent = '✕';
      els.alertBarText.innerHTML = `<strong>${escapeText(result.scamCategory)}:</strong> ${escapeText(result.staffNote)}`;
    } else if (result.verdict === 'caution') {
      els.messageDisplayBox.className = 'message-display-box is-caution';
      els.verdictRectBadge.className = 'verdict-rect-badge verdict-caution';
      els.verdictRectIcon.textContent = '!';
      els.verdictRectText.textContent = 'Verify First';
      els.footerAiSummary.textContent = 'Unverified contact number or message details';

      els.connectedAlertBar.className = 'connected-alert-bar verdict-caution';
      els.alertBarIcon.textContent = '!';
      els.alertBarText.innerHTML = `<strong>${escapeText(result.scamCategory)}:</strong> ${escapeText(result.staffNote)}`;
    } else {
      els.messageDisplayBox.className = 'message-display-box';
      els.verdictRectBadge.className = 'verdict-rect-badge verdict-safe';
      els.verdictRectIcon.textContent = '✓';
      els.verdictRectText.textContent = 'No Red Flags';
      els.footerAiSummary.textContent = 'AI scan complete · No obvious scam indicators detected';

      els.connectedAlertBar.className = 'connected-alert-bar verdict-safe';
      els.alertBarIcon.textContent = '✓';
      els.alertBarText.innerHTML = `<strong>${escapeText(result.scamCategory)}:</strong> ${escapeText(result.staffNote)}`;
    }

    if (result.warningSigns.length > 0) {
      els.warningList.innerHTML = result.warningSigns.map((flag, idx) => `
        <div class="numbered-card flag-card">
          <span class="num-badge">${idx + 1}</span>
          <div style="flex:1">
            <div class="card-title-row">
              <h4>${escapeText(flag.title)}</h4>
              ${flag.matchedText ? `<span class="matched-chip">"${escapeText(flag.matchedText)}"</span>` : ''}
            </div>
            <p>${escapeText(flag.detail)}</p>
          </div>
        </div>
      `).join('');
    } else {
      els.warningList.innerHTML = `
        <div class="numbered-card safe-card">
          <span class="num-badge">✓</span>
          <div>
            <div class="card-title-row"><h4>No High-Risk Scam Patterns Spotted</h4></div>
            <p>This contact number and message do not contain known phishing domains, urgency threats, or OTP harvesting requests.</p>
          </div>
        </div>
      `;
    }

    els.safeStepsList.innerHTML = result.safeSteps.map((step, idx) => `
      <div class="numbered-card safe-card">
        <span class="num-badge">${idx + 1}</span>
        <div>
          <div class="card-title-row"><h4>${escapeText(step.stepTitle)}</h4></div>
          <p>${escapeText(step.stepDetail)}</p>
        </div>
      </div>
    `).join('');
  }

  // Initialize region selector from user's timezone
  els.regionSelect.value = autoDetectRegion();

  els.phoneInput.addEventListener('input', runCheck);
  els.messageInput.addEventListener('input', runCheck);
  els.regionSelect.addEventListener('change', runCheck);

  els.checkerForm.addEventListener('submit', (e) => {
    e.preventDefault();
    runCheck();
    if (els.activeResultsWrap.style.display !== 'none') {
      els.activeResultsWrap.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });

  els.clearBtn.addEventListener('click', () => {
    els.phoneInput.value = '';
    els.messageInput.value = '';
    runCheck();
    els.phoneInput.focus();
  });

  els.fillExampleBtn.addEventListener('click', () => {
    const reg = els.regionSelect.value;
    if (reg === 'SG') {
      els.phoneInput.value = '+65 8391 0294';
      els.messageInput.value = 'DBS Alert: Unusual login activity detected on your digibank account. Verify immediately within 2 hours at dbs-secure-verify.xyz/unlock to prevent account suspension.';
    } else {
      els.phoneInput.value = '+1 (833) 502-9184';
      els.messageInput.value = 'Security Alert: Unusual activity detected! Your bank account has been suspended. Verify immediately within 2 hours at secure-account-verify.xyz/unlock to avoid permanent lock.';
    }
    runCheck();
  });

  els.verdictRectBadge.addEventListener('click', () => {
    document.getElementById('breakdownSection').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });
})();
