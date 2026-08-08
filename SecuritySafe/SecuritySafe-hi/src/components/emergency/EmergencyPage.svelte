<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { EmergencyPage } from '../../utils/emergency-data';

  export let page: EmergencyPage;

  const dispatch = createEventDispatcher();
  let checkedItems: Record<string, boolean> = {};

  function toggleCheck(id: string) {
    checkedItems[id] = !checkedItems[id];
    checkedItems = checkedItems;
  }
</script>

{#if page}
  <div class="page-container">
    <!-- Back Navigation -->
    <div class="page-nav">
      <button class="back-btn" on:click={() => dispatch('back')}>
        ← Back
      </button>
    </div>

    <!-- Header -->
    <section class="page-header">
      <div class="header-icon">{page.icon}</div>
      <h1>{page.title}</h1>
      <p class="header-subtitle">{page.subtitle}</p>
      {#if page.urgencyBadge}
        <div class="urgency-badge" class:warning={page.urgencyWarning}>
          {page.urgencyBadge}
        </div>
      {/if}
    </section>

    <!-- Immediate Steps -->
    <section class="section">
      <div class="section-header">
        <h2>⚡ Immediate Steps</h2>
        <p>Follow these in order</p>
      </div>
      <div class="steps-list">
        {#each page.steps as step, i}
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
                  <div class="action-info" class:warning={step.action.warning}>
                    {step.action.text}
                  </div>
                {/if}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    </section>

    <!-- Red Flags / How to Identify -->
    {#if page.redFlags || page.howToIdentify}
      <section class="section">
        <div class="section-header">
          <h2>{page.redFlags ? '🚩 Common Red Flags' : '🔍 How to Identify'}</h2>
          <p>Watch out for these signs</p>
        </div>
        <div class="flags-grid">
          {#each (page.redFlags || page.howToIdentify) as flag}
            <div class="flag-item">
              <span class="flag-icon">⚠️</span>
              <span>{flag}</span>
            </div>
          {/each}
        </div>
      </section>
    {/if}

    <!-- Legal Rights -->
    {#if page.legalRights}
      <section class="section">
        <div class="section-header">
          <h2>⚖️ Your Legal Rights</h2>
          <p>Laws that protect you in India</p>
        </div>
        <div class="legal-list">
          {#each page.legalRights as right}
            <div class="legal-item">
              <span class="legal-icon">📜</span>
              <span>{right}</span>
            </div>
          {/each}
        </div>
      </section>
    {/if}

    <!-- If That Fails -->
    {#if page.fallbacks && page.fallbacks.length > 0}
      <section class="section">
        <div class="section-header">
          <h2>⚠️ If That Fails</h2>
          <p>Escalation paths when initial steps don't work</p>
        </div>
        <div class="fallbacks-list">
          {#each page.fallbacks as fallback}
            <div class="fallback-card">
              <div class="fallback-trigger">
                <span class="trigger-icon">→</span>
                <span>{fallback.trigger}</span>
              </div>
              <div class="fallback-action">
                <p>{fallback.action}</p>
                {#if fallback.actionLink}
                  <a href={fallback.actionLink.url} target="_blank" rel="noopener noreferrer" class="action-btn">
                    🔗 {fallback.actionLink.text}
                  </a>
                {/if}
              </div>
            </div>
          {/each}
        </div>
      </section>
    {/if}

    <!-- Evidence to Preserve -->
    <section class="section">
      <div class="section-header">
        <h2>📁 Evidence to Preserve</h2>
        <p>Save these before anything gets deleted</p>
      </div>
      <div class="checklist">
        {#each page.evidence as item}
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

    <!-- Documents -->
    <section class="section">
      <div class="section-header">
        <h2>📄 Documents for Formal Complaint</h2>
        <p>Keep these ready</p>
      </div>
      <div class="documents-list">
        {#each page.documents as doc}
          <div class="document-item">
            <span class="doc-bullet">✓</span>
            <span>{doc}</span>
          </div>
        {/each}
      </div>
    </section>

    <!-- Footer -->
    {#if page.footerNote}
      <footer class="page-footer">
        <p>{@html page.footerNote.replace(/<strong>/g, '<strong>').replace(/<\/strong>/g, '</strong>')}</p>
      </footer>
    {/if}
  </div>
{:else}
  <div class="error-state">
    <p>No emergency page data loaded.</p>
  </div>
{/if}

<style is:global>
  .page-container {
    max-width: 800px;
    margin: 0 auto;
  }

  .error-state {
    padding: 40px 20px;
    text-align: center;
    color: #dc2626;
  }

  .page-nav {
    padding: 16px;
  }

  .back-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 8px 16px;
    background: transparent;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    color: #6b7280;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
    font-family: inherit;
  }

  .back-btn:hover {
    border-color: #d1d5db;
    color: #1f2937;
    background: #f9fafb;
  }

  .page-header {
    text-align: center;
    padding: 32px 20px;
    border-bottom: 1px solid #f3f4f6;
  }

  .header-icon {
    font-size: 40px;
    margin-bottom: 12px;
  }

  .page-header h1 {
    font-size: 24px;
    font-weight: 700;
    color: #1f2937;
    margin: 0 0 8px;
  }

  .header-subtitle {
    font-size: 14px;
    color: #6b7280;
    max-width: 600px;
    margin: 0 auto 16px;
    line-height: 1.6;
  }

  .urgency-badge {
    display: inline-block;
    padding: 6px 16px;
    background: #1f2937;
    color: #ffffff;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.5px;
  }

  .urgency-badge.warning {
    background: #dc2626;
  }

  .section {
    padding: 32px 16px;
    border-bottom: 1px solid #f3f4f6;
  }

  .section:last-of-type {
    border-bottom: none;
  }

  .section-header {
    margin-bottom: 20px;
  }

  .section-header h2 {
    font-size: 18px;
    font-weight: 600;
    color: #1f2937;
    margin: 0 0 4px;
  }

  .section-header p {
    font-size: 13px;
    color: #9ca3af;
    margin: 0;
  }

  .steps-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .step-card {
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    overflow: hidden;
    transition: all 0.2s ease;
  }

  .step-card:hover {
    border-color: #d1d5db;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
  }

  .step-card.checked {
    background: #f9fafb;
  }

  .step-card.checked .step-info h3 {
    text-decoration: line-through;
    color: #9ca3af;
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
    background: #2563eb;
    color: #ffffff;
    border-radius: 50%;
    font-size: 14px;
    font-weight: 600;
    flex-shrink: 0;
    margin-top: 2px;
  }

  .step-checkbox {
    width: 20px;
    height: 20px;
    border: 2px solid #d1d5db;
    border-radius: 4px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    margin-top: 6px;
    transition: all 0.2s ease;
  }

  .step-card.checked .step-checkbox {
    background: #2563eb;
    border-color: #2563eb;
    color: #ffffff;
  }

  .step-info {
    flex: 1;
  }

  .step-info h3 {
    font-size: 15px;
    font-weight: 600;
    color: #1f2937;
    margin: 0 0 4px;
    transition: all 0.2s ease;
  }

  .step-info p {
    font-size: 13px;
    color: #6b7280;
    margin: 0;
    line-height: 1.5;
  }

  .step-detail {
    padding: 0 16px 12px 60px;
  }

  .step-detail p {
    font-size: 12px;
    color: #6b7280;
    margin: 0;
    padding: 10px 12px;
    background: #f9fafb;
    border-left: 3px solid #e5e7eb;
    border-radius: 0 8px 8px 0;
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
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    color: #1f2937;
    font-size: 13px;
    font-weight: 500;
    text-decoration: none;
    transition: all 0.2s ease;
    font-family: inherit;
  }

  .action-btn:hover {
    background: #f9fafb;
    border-color: #d1d5db;
  }

  .action-btn.primary {
    background: #2563eb;
    color: #ffffff;
    border-color: #2563eb;
  }

  .action-btn.primary:hover {
    background: #1d4ed8;
    border-color: #1d4ed8;
  }

  .action-info {
    display: inline-block;
    padding: 8px 14px;
    background: #eff6ff;
    border: 1px solid #dbeafe;
    border-radius: 8px;
    font-size: 12px;
    color: #1e40af;
    font-weight: 500;
  }

  .action-info.warning {
    background: #fef2f2;
    border-color: #fecaca;
    color: #991b1b;
    font-weight: 600;
  }

  .flags-grid,
  .legal-list {
    display: grid;
    grid-template-columns: 1fr;
    gap: 8px;
  }

  @media (min-width: 600px) {
    .flags-grid,
    .legal-list {
      grid-template-columns: 1fr 1fr;
    }
  }

  .flag-item,
  .legal-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 12px;
    border-radius: 8px;
    font-size: 13px;
  }

  .flag-item {
    background: #fef2f2;
    border: 1px solid #fecaca;
    color: #991b1b;
  }

  .legal-item {
    background: #eff6ff;
    border: 1px solid #dbeafe;
    color: #1e40af;
  }

  .flag-icon,
  .legal-icon {
    font-size: 14px;
  }

  .fallbacks-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .fallback-card {
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    overflow: hidden;
  }

  .fallback-trigger {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 14px 16px;
    background: #f9fafb;
    border-bottom: 1px solid #f3f4f6;
    font-size: 13px;
    font-weight: 600;
    color: #1f2937;
  }

  .trigger-icon {
    font-size: 16px;
    font-weight: 700;
    flex-shrink: 0;
    margin-top: 1px;
    color: #2563eb;
  }

  .fallback-action {
    padding: 14px 16px;
  }

  .fallback-action p {
    font-size: 13px;
    color: #6b7280;
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
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.2s ease;
    font-size: 13px;
    user-select: none;
  }

  .checklist-item:hover {
    border-color: #d1d5db;
  }

  .checklist-item.checked {
    background: #f9fafb;
  }

  .checklist-item.checked span {
    text-decoration: line-through;
    color: #9ca3af;
  }

  .checklist-checkbox {
    width: 18px;
    height: 18px;
    border: 2px solid #d1d5db;
    border-radius: 3px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: all 0.2s ease;
  }

  .checklist-item.checked .checklist-checkbox {
    background: #2563eb;
    border-color: #2563eb;
    color: #ffffff;
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
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    font-size: 13px;
  }

  .doc-bullet {
    color: #2563eb;
    font-weight: 700;
    flex-shrink: 0;
    margin-top: 1px;
  }

  .page-footer {
    padding: 24px 16px 48px;
    text-align: center;
  }

  .page-footer p {
    font-size: 13px;
    color: #6b7280;
    margin: 0;
    line-height: 1.6;
  }

  .page-footer strong {
    color: #1f2937;
  }
</style>