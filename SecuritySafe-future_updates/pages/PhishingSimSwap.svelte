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
      id: 'p1',
      title: 'Do Not Click / Enter Details',
      description: 'If you haven\'t clicked or entered details yet, stop. Do not interact with the link.',
      action: { type: 'info', text: '🛑 STOP: Do not click further' }
    },
    {
      id: 'p2',
      title: 'If You Entered Bank/OTP Details',
      description: 'Immediately call your bank to block cards/freeze net banking. Treat as Financial Fraud.',
      detail: 'Time is critical. Call bank first, then 1930.',
      action: { type: 'call', number: '1930', text: 'Call 1930' }
    },
    {
      id: 'p3',
      title: 'If You Installed an APK',
      description: 'Put phone in Airplane Mode. Uninstall the app. Run security scan. Change passwords from a DIFFERENT clean device.',
      detail: 'Malicious APKs can steal data in background.'
    },
    {
      id: 'p4',
      title: 'If SIM Stopped Working (SIM Swap)',
      description: 'Contact telecom operator immediately to verify/block. Alert your bank instantly.',
      detail: 'SIM swap is usually a precursor to bank fraud.'
    },
    {
      id: 'p5',
      title: 'Report Phishing Link/SMS',
      description: 'Report to 1930 and forward SMS to telecom spam number (e.g., 1909).',
    }
  ];

  const howToIdentify = [
    'Urgent language ("Act now or account blocked")',
    'Generic greetings ("Dear Customer")',
    'Suspicious sender number or email address',
    'Links that don\'t match official domain (e.g., bank-name-support.com)',
    'Requests for OTP, PIN, or Password'
  ];

  const fallbacks = [
    {
      trigger: 'If SIM swap led to financial loss',
      action: 'Escalate as combined Financial Fraud + SIM Swap case. File with 1930 and bank simultaneously.'
    }
  ];

  const evidence = [
    { id: 'pe1', text: 'Screenshot of phishing SMS/email/link' },
    { id: 'pe2', text: 'Time of click and forms filled' },
    { id: 'pe3', text: 'Telecom complaint reference (for SIM swap)' },
    { id: 'pe4', text: 'Malicious APK file name (if installed)' }
  ];

  const documents = [
    'ID Proof',
    'Screenshot evidence',
    'Telecom/Bank reference numbers',
    '1930 complaint copy'
  ];
</script>

<div class="page-nav">
  <button class="back-btn" on:click={() => dispatch('back')}>
    ← Back to Emergency Guide
  </button>
</div>

<section class="page-header">
  <div class="header-icon">🔗</div>
  <h1>Phishing, SIM Swap & Malicious Links</h1>
  <p class="header-subtitle">Fake SMS, malicious APKs, SIM cloning, fake KYC links</p>
</section>

<section class="section">
  <div class="section-header">
    <h2>⚡ Immediate Steps</h2>
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
    <h2>🔍 How to Identify Phishing</h2>
  </div>
  <div class="red-flags-grid">
    {#each howToIdentify as flag}
      <div class="red-flag-item">
        <span class="flag-icon">⚠️</span>
        <span>{flag}</span>
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
  <p>🔒 <strong>Tip:</strong> Never share OTP, PIN, or Password. No bank or government agency will ever ask for these.</p>
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

  .red-flags-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 8px;
  }
  
  @media (min-width: 600px) {
    .red-flags-grid {
      grid-template-columns: 1fr 1fr;
    }
  }

  .red-flag-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px;
    background: #fff0f0;
    border: 1px solid #ffcccc;
    border-radius: var(--radius);
    font-size: 13px;
    color: #cc0000;
  }
  
  .flag-icon {
    font-size: 16px;
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