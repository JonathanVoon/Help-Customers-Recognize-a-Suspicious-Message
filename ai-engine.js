/**
 * SafeCheck AI — Production Client-Side Autonomous Scam Number & Message Engine
 * Analyzes real-world phone numbers (ITU E.164 prefixes, line types, carrier rules,
 * brand-sender mismatches) and message content (URLs, phishing domains, urgency,
 * OTP/credential traps, impersonation, and financial lures).
 */

(function (global) {
  'use strict';

  const COUNTRY_PREFIXES = [
    { code: '+1', iso: 'US/CA', name: 'United States / Canada (+1)' },
    { code: '+65', iso: 'SG', name: 'Singapore (+65)' },
    { code: '+44', iso: 'UK', name: 'United Kingdom (+44)' },
    { code: '+61', iso: 'AU', name: 'Australia (+61)' },
    { code: '+60', iso: 'MY', name: 'Malaysia (+60)' },
    { code: '+852', iso: 'HK', name: 'Hong Kong (+852)' },
    { code: '+63', iso: 'PH', name: 'Philippines (+63)' },
    { code: '+62', iso: 'ID', name: 'Indonesia (+62)' },
    { code: '+91', iso: 'IN', name: 'India (+91)' },
    { code: '+84', iso: 'VN', name: 'Vietnam (+84)' },
    { code: '+66', iso: 'TH', name: 'Thailand (+66)' },
    { code: '+86', iso: 'CN', name: 'China (+86)' },
    { code: '+81', iso: 'JP', name: 'Japan (+81)' },
    { code: '+82', iso: 'KR', name: 'South Korea (+82)' },
    { code: '+49', iso: 'DE', name: 'Germany (+49)' },
    { code: '+33', iso: 'FR', name: 'France (+33)' },
    { code: '+234', iso: 'NG', name: 'Nigeria (+234)' },
    { code: '+855', iso: 'KH', name: 'Cambodia (+855)' },
    { code: '+971', iso: 'AE', name: 'UAE (+971)' },
    { code: '+64', iso: 'NZ', name: 'New Zealand (+64)' }
  ].sort((a, b) => b.code.length - a.code.length);

  const OFFICIAL_BRANDS = [
    { name: 'PayPal', keywords: /\bpaypa[l1]\b/i, domains: ['paypal.com'] },
    { name: 'DBS / POSB', keywords: /\b(dbs|posb|digibank)\b/i, domains: ['dbs.com', 'dbs.com.sg', 'posb.com.sg'] },
    { name: 'OCBC', keywords: /\bocbc\b/i, domains: ['ocbc.com'] },
    { name: 'UOB', keywords: /\buob\b/i, domains: ['uob.com.sg', 'uobgroup.com'] },
    { name: 'Maybank', keywords: /\bmaybank\b/i, domains: ['maybank2u.com.my', 'maybank2u.com.sg', 'maybank.com'] },
    { name: 'Standard Chartered', keywords: /\b(standard\s*chartered|stanchart)\b/i, domains: ['sc.com'] },
    { name: 'Chase Bank', keywords: /\bchase\b/i, domains: ['chase.com'] },
    { name: 'Bank of America', keywords: /\b(bank\s*of\s*america|bofa)\b/i, domains: ['bankofamerica.com'] },
    { name: 'Wells Fargo', keywords: /\bwells\s*fargo\b/i, domains: ['wellsfargo.com'] },
    { name: 'Citibank', keywords: /\bciti(bank)?\b/i, domains: ['citi.com', 'citibank.com', 'citibank.com.sg'] },
    { name: 'HSBC', keywords: /\bhsbc\b/i, domains: ['hsbc.com', 'hsbc.co.uk', 'hsbc.com.sg', 'hsbc.com.hk'] },
    { name: 'Barclays', keywords: /\bbarclays\b/i, domains: ['barclays.co.uk', 'barclays.com'] },
    { name: 'Lloyds Bank', keywords: /\blloyds\b/i, domains: ['lloydsbank.com'] },
    { name: 'Commonwealth Bank', keywords: /\b(commbank|commonwealth\s*bank)\b/i, domains: ['commbank.com.au'] },
    { name: 'Apple', keywords: /\b(app[l1]e\s*id|icloud|apple\s*pay|app\s*store)\b/i, domains: ['apple.com', 'icloud.com'] },
    { name: 'Amazon', keywords: /\bamaz[o0]n\b/i, domains: ['amazon.com', 'amazon.sg', 'amazon.co.uk', 'amazon.com.au'] },
    { name: 'Netflix', keywords: /\bnetf[l1]ix\b/i, domains: ['netflix.com'] },
    { name: 'Microsoft', keywords: /\bmicros[o0]ft\b/i, domains: ['microsoft.com', 'live.com', 'office.com'] },
    { name: 'Google', keywords: /\bg[o0]{2}gle\b/i, domains: ['google.com', 'gmail.com'] },
    { name: 'WhatsApp', keywords: /\bwhatsapp\b/i, domains: ['whatsapp.com'] },
    { name: 'DHL', keywords: /\bdhl\b/i, domains: ['dhl.com'] },
    { name: 'FedEx', keywords: /\bfedex\b/i, domains: ['fedex.com'] },
    { name: 'USPS', keywords: /\busps\b/i, domains: ['usps.com'] },
    { name: 'UPS', keywords: /\bups\b/i, domains: ['ups.com'] },
    { name: 'Royal Mail', keywords: /\broyal\s*mail\b/i, domains: ['royalmail.com'] },
    { name: 'SingPost', keywords: /\bsingp[o0]st\b/i, domains: ['singpost.com'] },
    { name: 'Australia Post', keywords: /\b(auspost|australia\s*post)\b/i, domains: ['auspost.com.au'] },
    { name: 'Pos Malaysia', keywords: /\bpos\s*malaysia\b/i, domains: ['pos.com.my'] },
    { name: 'Government / Tax / Identity', keywords: /\b(irs|hmrc|iras|singpass|gov\.sg|cpf|medicare|social\s*security|mygov)\b/i, domains: ['irs.gov', 'gov.uk', 'iras.gov.sg', 'singpass.gov.sg', 'gov.sg', 'cpf.gov.sg', 'ssa.gov', 'my.gov.au'] }
  ];

  const URL_SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'rb.gy', 'cutt.ly', 'is.gd',
    'shorturl.at', 'tiny.cc', 'ow.ly', 'rebrand.ly', 's.id', 'lnkd.in', 'v.gd'
  ]);

  const RISKY_TLDS = /\.(xyz|top|click|vip|icu|buzz|loan|work|zip|mov|link|online|site|shop|live|rest|sbs|cfd|monster|quest|tk|ml|ga|cf)$/i;
  const URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>()"']+|(?:\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|net|org|gov|edu|co|io|sg|uk|us|au|my|hk|xyz|top|click|vip|icu|info|biz|me|ly|at|gy|cc|gd|id|online|site|shop|live|link|app|rest|sbs|cfd)(?:\/[^\s<>()"']*)?)/gi;

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function normalizePhone(input) {
    return String(input || '').replace(/[\s().-]/g, '');
  }

  function detectCountryPrefix(cleanPhone) {
    if (!cleanPhone.startsWith('+')) return null;
    for (const item of COUNTRY_PREFIXES) {
      if (cleanPhone.startsWith(item.code)) {
        return item;
      }
    }
    const genericMatch = cleanPhone.match(/^\+(\d{1,3})/);
    if (genericMatch) {
      return { code: '+' + genericMatch[1], iso: 'INTL', name: `International (+${genericMatch[1]})` };
    }
    return null;
  }

  function inspectNumberProfile(rawSender, userRegion = 'AUTO') {
    const trimmed = String(rawSender || '').trim();
    const clean = normalizePhone(trimmed);

    if (!trimmed) {
      return {
        display: 'Not provided',
        lineType: 'Waiting for input',
        origin: 'Enter a number above',
        formatStatus: 'None',
        isPhone: false
      };
    }

    const isDigits = /^\+?\d{4,16}$/.test(clean);
    if (!isDigits) {
      return {
        display: trimmed,
        lineType: 'Alphanumeric Sender ID',
        origin: 'One-way text label (no callback number)',
        formatStatus: /(-|_|\b(verify|alert|secure|support|refund)\b)/i.test(trimmed) ? 'Unverified Spoof Risk' : 'Text Sender ID',
        isPhone: false,
        isAlphaId: true
      };
    }

    const prefixInfo = detectCountryPrefix(clean);
    let origin = prefixInfo ? prefixInfo.name : 'Local / Domestic Dialing Format';
    let lineType = 'Standard Mobile or Landline';
    let formatStatus = 'Standard Format';

    if (/^\d{4,6}$/.test(clean)) {
      lineType = 'SMS Shortcode';
      origin = 'Automated Messaging Shortcode';
      formatStatus = 'Shortcode';
    } else if (/^\+?1?(800|833|844|855|866|877|888)\d{7}$/.test(clean)) {
      lineType = 'Toll-Free / Commercial VoIP';
      origin = 'North America Toll-Free';
      formatStatus = 'VoIP / Toll-Free';
    } else if (/^(\+?1?900\d{7}|090\d{6,}|1900\d{5,})$/.test(clean)) {
      lineType = 'Premium-Rate Billing Line';
      origin = 'Pay-Per-Minute Service';
      formatStatus = 'High Cost Risk';
    } else if (/^\+65[689]\d{7}$/.test(clean)) {
      lineType = 'Displays "+65" International Prefix';
      origin = 'Singapore (+65 Prefix Shown)';
      formatStatus = 'Spoofed Overseas Call/SMS Risk';
    } else if (/^[89]\d{7}$/.test(clean) && (userRegion === 'SG' || userRegion === 'AUTO')) {
      lineType = 'Domestic Mobile Number';
      origin = 'Local 8-Digit Mobile';
      formatStatus = 'Regular Mobile Line';
    } else if (prefixInfo) {
      lineType = `International Line (${prefixInfo.code})`;
      formatStatus = (userRegion !== 'AUTO' && userRegion !== prefixInfo.iso)
        ? `Foreign Origin (${prefixInfo.code})`
        : `International Format (${prefixInfo.code})`;
    }

    return {
      display: trimmed,
      lineType,
      origin,
      formatStatus,
      prefixInfo,
      isPhone: true
    };
  }

  function extractHost(rawUrl) {
    const cleaned = rawUrl.replace(/[.,!?;:)\]]+$/, '');
    const withProto = /^https?:\/\//i.test(cleaned) ? cleaned : 'https://' + cleaned;
    try {
      const u = new URL(withProto);
      return { raw: cleaned, host: u.hostname.toLowerCase().replace(/^www\./, '') };
    } catch (_) {
      const hostMatch = cleaned.replace(/^https?:\/\//i, '').replace(/^www\./i, '').split('/')[0];
      return { raw: cleaned, host: (hostMatch || '').toLowerCase() };
    }
  }

  function domainMatchesOfficial(host, officialDomains) {
    return officialDomains.some((off) => host === off || host.endsWith('.' + off));
  }

  function analyzeMessage(text, sender = '', userRegion = 'AUTO') {
    const rawText = (text || '').trim();
    const rawSender = (sender || '').trim();
    const cleanPhone = normalizePhone(rawSender);
    const numberProfile = inspectNumberProfile(rawSender, userRegion);

    if (!rawText && !rawSender) {
      return {
        empty: true,
        verdict: 'safe',
        riskScore: 0,
        confidence: 0,
        badgeLabel: 'Ready',
        scamCategory: 'Enter a Contact Number or Message Above',
        staffNote: 'Type the phone number or sender ID that contacted you (and paste their message if you received one) to run an instant safety check.',
        warningSigns: [],
        safeSteps: [],
        highlightedHtml: '',
        numberProfile
      };
    }

    let score = 0;
    const warningSigns = [];
    const highlightTerms = [];
    const categories = new Set();

    function addFlag(points, title, detail, matchedText, category, severity = 'high') {
      score += points;
      if (category) categories.add(category);
      warningSigns.push({ title, detail, matchedText, severity });
      if (matchedText && matchedText.length >= 3) {
        highlightTerms.push(matchedText);
      }
    }

    const detectedBrands = OFFICIAL_BRANDS.filter(
      (b) => b.keywords.test(rawText) || b.keywords.test(rawSender)
    );

    // --- 1. PHONE NUMBER & SENDER FORENSICS ---
    if (rawSender) {
      // A. Premium-rate billing number
      if (/^(\+?1?900\d{7}|090\d{6,}|1900\d{5,})$/.test(cleanPhone)) {
        addFlag(
          55,
          `Premium-rate billing number (${rawSender})`,
          `Numbers starting with 900 / 090 / 1900 can bill high per-minute charges if you call or text them back.`,
          '',
          'number',
          'high'
        );
      }

      // B. "+65" prefix spoofing rule (telecom anti-scam rule in SG)
      if (/^\+65\d{8}$/.test(cleanPhone)) {
        addFlag(
          38,
          `Displays "+65" prefix (${rawSender}) — overseas spoofing indicator`,
          `Genuine local calls and texts in Singapore do not display the "+65" prefix unless the caller is roaming overseas. Scammers spoof "+65" from foreign VoIP servers.`,
          '',
          'number',
          'high'
        );
      }

      // C. Cross-border country code mismatch when user selected a home region
      if (
        numberProfile.prefixInfo &&
        userRegion !== 'AUTO' &&
        numberProfile.prefixInfo.iso !== userRegion
      ) {
        addFlag(
          32,
          `Foreign country code (${numberProfile.prefixInfo.code}) does not match your region (${userRegion})`,
          `This contact number originates from ${numberProfile.prefixInfo.name}. Local banks, couriers, and government agencies do not contact customers from overseas phone lines.`,
          '',
          'number',
          'high'
        );
      } else if (/^\+(63|234|855|62|84|7)\d+/.test(cleanPhone) && userRegion === 'AUTO') {
        addFlag(
          30,
          `Overseas international dialing prefix (${numberProfile.prefixInfo ? numberProfile.prefixInfo.code : rawSender})`,
          `Be extra cautious when unexpected bank, parcel, or job messages arrive from an unfamiliar international country code.`,
          '',
          'number',
          'high'
        );
      }

      // D. Suspicious Alphanumeric Sender ID
      if (
        numberProfile.isAlphaId &&
        /(-|_|\b(support|alert|verify|refund|security|desk|admin|locked|notice)\b)/i.test(rawSender)
      ) {
        addFlag(
          28,
          `Unverified sender ID "${rawSender}"`,
          `Scammers use generic sender labels like "${rawSender}" to look official while hiding their actual phone number.`,
          '',
          'number',
          'high'
        );
      }

      // E. Regular mobile or unverified toll-free number claiming to be a major Bank / Courier / Gov
      if (numberProfile.isPhone && detectedBrands.length > 0 && !/^\d{4,6}$/.test(cleanPhone)) {
        const brandNames = detectedBrands.map((b) => b.name).join(' / ');
        addFlag(
          28,
          `Phone number (${rawSender}) does not match official ${brandNames} SMS channels`,
          `The message mentions ${brandNames}, but came from a ${numberProfile.lineType.toLowerCase()} rather than a verified official sender channel.`,
          '',
          'number',
          'high'
        );
      }

      // F. Number checked by itself without message text
      if (!rawText && score === 0) {
        if (/^\+?1?(800|833|844|855|866|877|888)\d{7}$/.test(cleanPhone)) {
          addFlag(
            20,
            `Unverified Toll-Free / VoIP number (${rawSender})`,
            `Scammers frequently rent 833/844/888 toll-free numbers for automated phishing texts and robocalls. Always verify the number on the company's official website before calling back.`,
            '',
            'number',
            'medium'
          );
        } else if (numberProfile.isPhone) {
          addFlag(
            15,
            `Caller ID (${rawSender}) can be spoofed — verify before calling back`,
            `A phone number alone cannot prove identity because scammers can spoof local numbers. If they sent a text or left a voicemail, paste the message above so our AI can inspect their links and wording.`,
            '',
            'number',
            'medium'
          );
        }
      }
    }

    // --- 2. MESSAGE CONTENT & URL FORENSICS ---
    if (rawText) {
      const rawMatches = rawText.match(URL_REGEX) || [];
      const urls = rawMatches
        .filter((m) => !/@/.test(m))
        .map(extractHost)
        .filter((u) => u.host && u.host.includes('.'));

      urls.forEach((u) => {
        let urlFlagged = false;

        if (URL_SHORTENERS.has(u.host)) {
          addFlag(
            35,
            `Shortened link (${u.host}) hides the real website address`,
            `The link "${u.raw}" uses a link shortener so you cannot see the actual destination domain before tapping.`,
            u.raw,
            'link',
            'high'
          );
          urlFlagged = true;
        }

        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.host)) {
          addFlag(
            45,
            'Link uses a raw IP address instead of a real company domain',
            `"${u.raw}" points to a raw numeric server address rather than an official website.`,
            u.raw,
            'link',
            'high'
          );
          urlFlagged = true;
        }

        if (/(paypa1|amaz0n|app1e|micros0ft|netf1ix|g00gle|singp0st)/i.test(u.host)) {
          addFlag(
            50,
            'Lookalike character-swap trick in website domain',
            `Look closely at "${u.host}" — digits like "1" or "0" replace letters to impersonate a trusted brand.`,
            u.raw,
            'phishing',
            'high'
          );
          urlFlagged = true;
        }

        if (detectedBrands.length > 0) {
          const matchesBrand = detectedBrands.some((b) => domainMatchesOfficial(u.host, b.domains));
          if (!matchesBrand) {
            const brandNames = detectedBrands.map((b) => b.name).join(' / ');
            addFlag(
              44,
              `Link domain (${u.host}) does not belong to ${brandNames}`,
              `The message claims to be from ${brandNames}, but the link directs you to "${u.host}" instead of their official website.`,
              u.raw,
              'phishing',
              'high'
            );
            urlFlagged = true;
          }
        }

        if (
          !urlFlagged &&
          (/(-verify|-secure|-login|-update|-unlock|-account|-alert|-auth|-claim|-parcel|-refund|verify-|secure-)/i.test(u.host) ||
            RISKY_TLDS.test(u.host))
        ) {
          addFlag(
            38,
            `High-risk lookalike domain (${u.host})`,
            `Scammers register domains with words like "-verify" or "-secure" and disposable domain endings (.xyz, .top, .click) to mimic real alerts.`,
            u.raw,
            'phishing',
            'high'
          );
          urlFlagged = true;
        }

        if (!urlFlagged) {
          score += 8;
          highlightTerms.push(u.raw);
        }
      });

      const urgencyMatch = rawText.match(/\b(immediately|urgent(ly)?|within\s+\d+\s*(hours?|hrs?|mins?|minutes?)|final\s+(notice|warning|reminder)|act\s+now|expires?\s+(today|soon)|avoid\s+(permanent\s+)?(lock|suspension))\b/i);
      if (urgencyMatch) {
        addFlag(
          25,
          'High-pressure countdown or urgency tactic',
          `Phrases like "${urgencyMatch[0]}" are designed to rush you into acting before you can verify the contact number calmly.`,
          urgencyMatch[0],
          'urgency',
          'high'
        );
      }

      const threatMatch = rawText.match(/\b(account\s+(has\s+been\s+|is\s+|will\s+be\s+)?(suspended|locked|frozen|restricted|disabled|blocked)|unusual\s+(login|activity)|unauthorized\s+(\$?\d+(\.\d{2})?\s+)?(transaction|access|login|charge)|security\s+alert|legal\s+action|arrest\s+warrant|customs\s+seizure)\b/i);
      if (threatMatch) {
        addFlag(
          28,
          'Account scare or security threat',
          `Claims like "${threatMatch[0]}" trigger fear about your money or legal standing so you react without checking.`,
          threatMatch[0],
          'bank',
          'high'
        );
      }

      const otpMatch = rawText.match(/\b((share|reply|send|provide).{0,30}(otp|verification\s+code|6-digit|pin|password)|enter\s+your\s+(pin|password|cvv|otp|singpass))\b/i);
      const legOtpWarning = /\b(never\s+share|do\s+not\s+share|don't\s+share)\b/i.test(rawText);
      if (otpMatch && !legOtpWarning) {
        addFlag(
          50,
          'Asks you to share a secret OTP, PIN, or password',
          `Real staff will NEVER ask you to reply with, read out, or enter your OTP code, PIN, or password via a text message.`,
          otpMatch[0],
          'credentials',
          'high'
        );
      }

      const remoteMatch = rawText.match(/\b(anydesk|teamviewer|quicksupport|download\s+(this\s+|our\s+)?apk|\.apk\b)/i);
      if (remoteMatch) {
        addFlag(
          52,
          'Requests remote-access tool or unofficial APK app',
          `Mentions "${remoteMatch[0]}" — scammers use remote desktop apps or side-loaded APK files to take control of your device.`,
          remoteMatch[0],
          'malware',
          'high'
        );
      }

      const parcelMatch = rawText.match(/\b(redelivery\s+fee|customs\s+(fee|duty)|unpaid\s+(postage|shipping|fee)|incomplete\s+address|delivery\s+(on\s+hold|failed|suspended))\b/i);
      if (parcelMatch && (urls.length > 0 || /\$\s*\d+(\.\d{2})?/.test(rawText))) {
        addFlag(
          34,
          'Small-fee parcel delivery trap',
          `Claims about "${parcelMatch[0]}" asking for a small payment via a link are used to harvest credit card numbers and OTPs.`,
          parcelMatch[0],
          'parcel',
          'high'
        );
      }

      const familyScamMatch = rawText.match(/\b(hi\s+(mum|mom|dad)|hey\s+(mum|mom|dad)).{0,80}\b(new\s+number|lost\s+my\s+phone|broke\s+my\s+phone|dropped\s+my\s+phone|message\s+me\s+on\s+whatsapp)\b/i);
      if (familyScamMatch) {
        addFlag(
          46,
          '"Broken phone / new number" family impersonation',
          `Pretending to be a family member texting from a new number is a widespread scam that leads to an urgent money transfer request.`,
          familyScamMatch[0],
          'impersonation',
          'high'
        );
      }

      const jobLureMatch = rawText.match(/\b(you\s+(have\s+)?won|unclaimed\s+(reward|prize|refund)|tax\s+refund|earn\s+\$?\d+\s*(\/\s*day|per\s+day|daily)|part[-\s]?time\s+remote\s+job|usdt\s+reward|guaranteed\s+return)\b/i);
      if (jobLureMatch) {
        addFlag(
          38,
          'Unexpected prize, refund, or easy-money job offer',
          `Unsolicited offers like "${jobLureMatch[0]}" are used in task scams and advance-fee fraud.`,
          jobLureMatch[0],
          'lure',
          'high'
        );
      }
    }

    const riskScore = Math.min(99, Math.max(0, score));
    let verdict = 'safe';
    let badgeLabel = 'No Red Flags';
    if (riskScore >= 32) {
      verdict = 'suspicious';
      badgeLabel = 'Suspicious';
    } else if (riskScore >= 14) {
      verdict = 'caution';
      badgeLabel = 'Verify First';
    }

    let scamCategory = 'No Obvious Scam Patterns Detected';
    let staffNote = 'We did not detect high-risk scam indicators in what you entered, though you should always verify independently before sending money or sharing personal details.';
    let safeSteps = [
      {
        stepTitle: 'Compare the phone number against an official source',
        stepDetail: 'Before calling back or replying, verify the number on the back of your physical bank card, bill, or the organization\'s official website.'
      },
      {
        stepTitle: 'Stay cautious if the conversation shifts to money or codes',
        stepDetail: 'Even if an initial message looks normal, pause immediately if anyone asks for an OTP, payment, or personal ID.'
      }
    ];

    if (verdict === 'suspicious') {
      if (categories.has('credentials') || categories.has('malware')) {
        scamCategory = 'Account Takeover / Credential Scam';
        staffNote = 'Do not reply to this contact number or share any codes! Real staff will never ask for your OTP, PIN, password, or ask you to install remote-control apps.';
        safeSteps = [
          {
            stepTitle: 'Block this contact number and do not reply',
            stepDetail: 'Never share a 6-digit OTP, PIN, or password with anyone over text or phone.'
          },
          {
            stepTitle: 'Call the official number printed on the back of your card',
            stepDetail: 'Do not dial numbers given inside a suspicious text. Use the number on your physical card or official banking app.'
          },
          {
            stepTitle: 'Check your account directly inside the official app',
            stepDetail: 'Open your trusted banking app from your home screen to verify whether any real security alert exists.'
          }
        ];
      } else if (categories.has('parcel')) {
        scamCategory = 'Fake Courier / Delivery Fee Scam';
        staffNote = 'Do not pay any fee on that link! Scammers send fake delivery alerts from random numbers to steal your credit card details.';
        safeSteps = [
          {
            stepTitle: 'Do not tap the link or call this sender number',
            stepDetail: 'Real couriers do not text random mobile or shortened links demanding immediate card payments.'
          },
          {
            stepTitle: 'Check your order inside the official shopping app',
            stepDetail: 'Open the app where you placed your order (or type the courier\'s real website yourself) to check real tracking.'
          },
          {
            stepTitle: 'Block and report the sender number as spam',
            stepDetail: 'Use your phone\'s "Report Junk / Block" option so this number cannot contact you again.'
          }
        ];
      } else if (categories.has('impersonation')) {
        scamCategory = 'Family / "New Number" Impersonation Scam';
        staffNote = 'Pause before saving this number or messaging on WhatsApp — scammers pretend to be a relative with a broken phone right before asking for an urgent transfer.';
        safeSteps = [
          {
            stepTitle: 'Call your family member\'s original saved number first',
            stepDetail: 'Dial the old number already stored in your contacts to check if their phone is truly broken.'
          },
          {
            stepTitle: 'Insist on a real voice or video call',
            stepDetail: 'Ask a personal question only your real relative would know before agreeing to pay any bill.'
          },
          {
            stepTitle: 'Refuse urgent transfers to unfamiliar bank accounts',
            stepDetail: 'Never rush money to a "friend\'s account" requested over text.'
          }
        ];
      } else {
        scamCategory = 'Suspicious Number & Phishing Alert';
        staffNote = 'Hold on — this contact number and message show high-risk scam warning signs. Do not call this number back or tap any links before checking safely below.';
        safeSteps = [
          {
            stepTitle: 'Do not call this number or tap any link in the message',
            stepDetail: 'Scammers control both the websites and the callback numbers placed inside fake alert messages.'
          },
          {
            stepTitle: 'Contact the organization using an independently verified number',
            stepDetail: 'Look up the official support number on the back of your bank card, a printed statement, or the official app.'
          },
          {
            stepTitle: 'Block the number after confirming your account is safe',
            stepDetail: 'Once you check via your official app that everything is fine, block and report this sender.'
          }
        ];
      }
    } else if (verdict === 'caution') {
      scamCategory = 'Unverified Contact Number — Check Before Acting';
      staffNote = 'Caller IDs can be spoofed. Follow the numbered steps below to verify who really contacted you before calling back or replying.';
      safeSteps = [
        {
          stepTitle: 'Look up the organization\'s official number yourself',
          stepDetail: 'Visit the company\'s official website directly and compare their listed phone number with the one that contacted you.'
        },
        {
          stepTitle: 'Paste the full message they sent you',
          stepDetail: 'If this number texted you or left a voicemail transcript, paste the exact words in Step 2 so our AI can scan for hidden traps.'
        },
        {
          stepTitle: 'Never share personal or banking details on an unverified call',
          stepDetail: 'If someone calls claiming an urgent issue, hang up and call back on the official number from your card or statement.'
        }
      ];
    }

    let highlightedHtml = escapeHtml(rawText);
    const uniqueTerms = Array.from(new Set(highlightTerms.filter(Boolean))).sort((a, b) => b.length - a.length);
    const placeholders = [];
    uniqueTerms.forEach((term) => {
      const escapedTerm = escapeHtml(term);
      const safePattern = escapedTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(safePattern, 'gi');
      highlightedHtml = highlightedHtml.replace(regex, (match) => {
        const pIdx = placeholders.length;
        placeholders.push(`<mark class="scam-highlight">${match}</mark>`);
        return `@@SC_TOK_${pIdx}@@`;
      });
    });
    highlightedHtml = highlightedHtml.replace(/@@SC_TOK_(\d+)@@/g, (_, n) => placeholders[Number(n)]);

    return {
      empty: false,
      verdict,
      riskScore,
      badgeLabel,
      scamCategory,
      staffNote,
      warningSigns,
      safeSteps,
      highlightedHtml,
      numberProfile
    };
  }

  global.SafeCheckAI = {
    analyzeMessage
  };
})(typeof window !== 'undefined' ? window : globalThis);
