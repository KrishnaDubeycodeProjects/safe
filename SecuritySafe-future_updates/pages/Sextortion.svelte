<script>
  import { createEventDispatcher } from 'svelte';
  const dispatch = createEventDispatcher();

  let checkedItems = {};

  function toggleCheck(id) {
    checkedItems[id] = !checkedItems[id];
    checkedItems = checkedItems;
  }

  const steps = [
    {
      id: 's1',
      title: 'DO NOT PAY',
      description: 'Paying almost never stops it. It usually invites repeat demands. Do not send any more money or images.',
      detail: 'Scammers rely on fear. Payment confirms you are willing to pay, making you a target for life.',
      action: { type: 'info', text: '🛑 STOP: Do not transfer money' }
    },
    {
      id: 's2',
      title: 'Preserve Evidence (Do Not Delete)',
      description: 'Do not delete the chat, images, or the blackmailer\'s profile. Screenshot everything first.',
      detail: 'Capture their username, profile link, messages, and any payment demands. Only block AFTER screenshotting.',
    },
    {
      id: 's3',
      title: 'Use StopNCII.org',
      description: 'A free, confidential global tool. Create a digital "hash" of the image so platforms (Meta, TikTok) can detect and block it.',
      detail: 'You do NOT send the actual image to them. It creates a digital fingerprint locally on your device.',
      action: { type: 'link', url: 'https://stopncii.org', text: 'Visit StopNCII.org' }
    },
    {
      id: 's4',
      title: 'Report on Cyber Crime Portal',
      description: 'File under "Report Women/Child Related Crime". Allows anonymous reporting if you are not ready to reveal identity.',
      action: { type: 'link', url: 'https://cybercrime.gov.in', text: 'File Anonymous Report' }
    },
    {
      id: 's5',
      title: 'Call 1930',
      description: 'They have officers trained specifically for sextortion and NCII (Non-Consensual Intimate Imagery) cases.',
      action: { type: 'call', number: '1930', text: 'Call 1930 Now' }
    },
    {
      id: 's6',
      title: 'Report on Platform',
      description: 'Use Instagram/Facebook/WhatsApp "Report" feature. Select "Non-consensual intimate imagery" or "Sexual exploitation".',
      detail: 'This can get content taken down within hours if flagged correctly.'
    }
  ];

  const fallbacks = [
    {
      trigger: 'If content is already public',
      action: 'Use each platform\'s takedown request AND file with cybercrime.gov.in simultaneously. Request expedited removal citing active police complaint.'
    },
    {
      trigger: 'If blackmailer uses new numbers/accounts',
      action: 'Report each new contact to 1930 referencing your ORIGINAL complaint number. Do not start fresh cases.'
    }
  ];

  const evidence = [
    { id: 'se1', text: 'Screenshots of all threats/messages (with timestamps)' },
    { id: 'se2', text: 'Blackmailer\'s profile link/username/phone number' },
    { id: 'se3', text: 'Payment demand details (UPI ID, Wallet address)' },
    { id: 'se4', text: 'StopNCII case reference (if used)' }
  ];

  const documents = [
    'ID Proof (Optional for anonymous filing)',
    'Screenshot evidence',
    'Platform report reference numbers',
    '1930 complaint reference'
  ];
</script>

<div class="page-nav">
  <button class="back-btn" on:click={() => dispatch('back')}>
    ← Back to Emergency Guide
  </button>
</div>

<section class="page-header">
  <div class="header-icon">📸</div>
  <h1>Intimate Image Blackmail</h1>
  <p class="header-subtitle">Sextortion, leaked private photos, webcam blackmail, NCII</p>
  <div class="urgency-badge warning">🛑 DO NOT PAY</div>
</section>

<section class="section">
  <div class="section-header">
    <h2>⚡ Immediate Steps</h2>
    <p>Follow these strictly. Isolation is what scammers want.</p>
  </div>
  <div class="steps-list">
    {#each steps as step, i}
      <div class="step-card" class:checked={checkedItems[step.id]}>
        <div class="step-header" on:click={() => toggleCheck(step.id)} role="checkbox" aria-checked={checkedItems[step.id]} tabindex="0" on:keydown={(e) => e.key === 'Enter' && toggleCheck(step.id)}>
          <div class="step-number">{i + 1}</div>
          <div class="step-checkbox">
            {#if checkedItems[step.id]}
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
            {/if}
          </div>
          <div class="step-info">
            <h3>{step.title}</h3>
            <p>{step.description}</p>
          </div>
        </div>
        {#if step.detail}
          <div class="step-detail">
            <p>{step.detail}</p>
          </div>
        {/if}
        {#if step.action}
          <div class="step-action-row">
            {#if step.action.type === 'call'}
              <a href="tel:{step.action.number}" class="action-btn primary">
                📞 {step.action.text}
              </a>
            {:else if step.action.type === 'link'}
              <a href={step.action.url} target="_blank" rel="noopener noreferrer" class="action-btn">
                🔗 {step.action.text}
              </a>
            {:else if step.action.type === 'info'}
              <div class="action-info warning">
                {step.action.text}
              </div>
            {/if}
          </div>
        {/if}
      </div>
    {/each}
  </div>
</section>

<section class="section">
  <div class="section-header">
    <h2>⚠️ If That Fails</h2>
  </div>
  <div class="fallbacks-list">
    {#each fallbacks as fallback}
      <div class="fallback-card">
        <div class="fallback-trigger">
          <span class="trigger-icon">→</span>
          <span>{fallback.trigger}</span>
        </div>
        <div class="fallback-action">
          <p>{fallback.action}</p>
        </div>
      </div>
    {/each}
  </div>
</section>

<section class="section">
  <div class="section-header">
    <h2>📁 Evidence to Preserve</h2>
  </div>
  <div class="checklist">
    {#each evidence as item}
      <div
        class="checklist-item"
        class:checked={checkedItems[item.id]}
        on:click={() => toggleCheck(item.id)}
        role="checkbox"
        aria-checked={checkedItems[item.id]}
        tabindex="0"
        on:keydown={(e) => e.key === 'Enter' && toggleCheck(item.id)}
      >
        <div class="checklist-checkbox">
          {#if checkedItems[item.id]}
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="20 6 9 17 4 12"/>
            </svg>
          {/if}
        </div>
        <span>{item.text}</span>
      </div>
    {/each}
  </div>
</section>

<section class="section">
  <div class="section-header">
    <h2>📄 Documents for Formal Complaint</h2>
  </div>
  <div class="documents-list">
    {#each documents as doc}
      <div class="document-item">
        <span class="doc-bullet">✓</span>
        <span>{doc}</span>
      </div>
    {/each}
  </div>
</section>

<footer class="page-footer">
  <p>💙 <strong>You are not alone.</strong> Tell someone you trust. Isolation helps the scammer. You did nothing wrong.</p>
</footer>

<style is:global>
  .page-nav {
    max-width: 800px;
    margin: 0 auto;
    padding: 16px 16px 0;
  }

  .back-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 8px 16px;
    background: transparent;
    border: 1px solid var(--border-light);
    border-radius: var(--radius);
    color: var(--text-dim);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
    font-family: inherit;
  }

  .back-btn:hover {
    border-color: var(--border);
    color: var(--text);
    background: var(--bg-card);
  }

  .page-header {
    text-align: center;
    padding: 32px 20px;
    border-bottom: 1px solid var(--border-light);
  }

  .header-icon {
    font-size: 40px;
    margin-bottom: 12px;
  }

  .page-header h1 {
    font-family: var(--font-heading);
    font-size: 24px;
    font-weight: 800;
    color: var(--text);
    margin: 0 0 8px;
  }

  .header-subtitle {
    font-size: 14px;
    color: var(--text-dim);
    max-width: 600px;
    margin: 0 auto 16px;
    line-height: 1.6;
  }

  .urgency-badge {
    display: inline-block;
    padding: 6px 16px;
    background: var(--text);
    color: var(--accent-text);
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.5px;
  }
  
  .urgency-badge.warning {
    background: #ff0000;
  }

  .section {
    max-width: 800px;
    margin: 0 auto;
    padding: 32px 16px;
    border-bottom: 1px solid var(--border-light);
  }

  .section:last-of-type {
    border-bottom: none;
  }

  .section-header {
    margin-bottom: 20px;
  }

  .section-header h2 {
    font-family: var(--font-heading);
    font-size: 20px;
    font-weight: 700;
    color: var(--text);
    margin: 0 0 4px;
  }

  .section-header p {
    font-size: 14px;
    color: var(--text-dim);
    margin: 0;
  }

  .steps-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .step-card {
    background: var(--bg-card);
    border: 1px solid var(--border-light);
    border-radius: var(--radius-lg);
    overflow: hidden;
    transition: all 0.2s ease;
  }

  .step-card:hover {
    border-color: var(--border-medium);
    box-shadow: var(--shadow);
  }

  .step-card.checked {
    background: #f8f8f8;
  }

  .step-card.checked .step-info h3 {
    text-decoration: line-through;
    color: var(--text-light);
  }

  .step-header {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 16px;
    cursor: pointer;
    user-select: none;
  }

  .step-number {
    width: 32px;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--text);
    color: var(--accent-text);
    border-radius: 50%;
    font-size: 14px;
    font-weight: 700;
    flex-shrink: 0;
    margin-top: 2px;
  }

  .step-checkbox {
    width: 20px;
    height: 20px;
    border: 2px solid var(--border);
    border-radius: 4px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    margin-top: 6px;
    transition: all 0.2s ease;
  }

  .step-card.checked .step-checkbox {
    background: var(--text);
    border-color: var(--text);
    color: var(--accent-text);
  }

  .step-info {
    flex: 1;
  }

  .step-info h3 {
    font-size: 16px;
    font-weight: 700;
    color: var(--text);
    margin: 0 0 4px;
    transition: all 0.2s ease;
  }

  .step-info p {
    font-size: 14px;
    color: var(--text-dim);
    margin: 0;
    line-height: 1.5;
  }

  .step-detail {
    padding: 0 16px 12px 60px;
  }

  .step-detail p {
    font-size: 13px;
    color: var(--text-dim);
    margin: 0;
    padding: 10px 12px;
    background: #f8f8f8;
    border-left: 3px solid var(--border);
    border-radius: 0 var(--radius) var(--radius) 0;
    line-height: 1.5;
  }

  .step-action-row {
    padding: 0 16px 16px 60px;
  }

  .action-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 10px 18px;
    background: var(--bg-card);
    border: 2px solid var(--border);
    border-radius: var(--radius);
    color: var(--text);
    font-size: 13px;
    font-weight: 600;
    text-decoration: none;
    transition: all 0.2s ease;
    font-family: inherit;
  }

  .action-btn:hover {
    background: var(--text);
    color: var(--accent-text);
  }

  .action-btn.primary {
    background: var(--text);
    color: var(--accent-text);
    border-color: var(--text);
  }

  .action-btn.primary:hover {
    background: #333333;
    border-color: #333333;
  }

  .action-info {
    display: inline-block;
    padding: 8px 14px;
    background: #f8f8f8;
    border: 1px solid var(--border-light);
    border-radius: var(--radius);
    font-size: 13px;
    color: var(--text-dim);
    font-weight: 500;
  }
  
  .action-info.warning {
    background: #fff0f0;
    border-color: #ffcccc;
    color: #cc0000;
    font-weight: 700;
  }

  .fallbacks-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .fallback-card {
    background: var(--bg-card);
    border: 1px solid var(--border-light);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }

  .fallback-trigger {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 14px 16px;
    background: #f8f8f8;
    border-bottom: 1px solid var(--border-light);
    font-size: 14px;
    font-weight: 600;
    color: var(--text);
  }

  .trigger-icon {
    font-size: 16px;
    font-weight: 700;
    flex-shrink: 0;
    margin-top: 1px;
  }

  .fallback-action {
    padding: 14px 16px;
  }

  .fallback-action p {
    font-size: 14px;
    color: var(--text-dim);
    margin: 0 0 12px;
    line-height: 1.6;
  }

  .checklist {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .checklist-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    background: var(--bg-card);
    border: 1px solid var(--border-light);
    border-radius: var(--radius);
    cursor: pointer;
    transition: all 0.2s ease;
    font-size: 14px;
    user-select: none;
  }

  .checklist-item:hover {
    border-color: var(--border-medium);
  }

  .checklist-item.checked {
    background: #f8f8f8;
  }

  .checklist-item.checked span {
    text-decoration: line-through;
    color: var(--text-light);
  }

  .checklist-checkbox {
    width: 18px;
    height: 18px;
    border: 2px solid var(--border);
    border-radius: 3px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: all 0.2s ease;
  }

  .checklist-item.checked .checklist-checkbox {
    background: var(--text);
    border-color: var(--text);
    color: var(--accent-text);
  }

  .documents-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .document-item {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 14px;
    background: var(--bg-card);
    border: 1px solid var(--border-light);
    border-radius: var(--radius);
    font-size: 14px;
  }

  .doc-bullet {
    color: var(--text);
    font-weight: 700;
    flex-shrink: 0;
    margin-top: 1px;
  }

  .page-footer {
    max-width: 800px;
    margin: 0 auto;
    padding: 24px 16px 48px;
    text-align: center;
  }

  .page-footer p {
    font-size: 14px;
    color: var(--text-dim);
    margin: 0;
    line-height: 1.6;
  }

  .page-footer strong {
    color: var(--text);
  }
</style>