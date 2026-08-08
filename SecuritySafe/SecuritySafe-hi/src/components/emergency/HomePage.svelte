<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { emergencyContacts, universalSteps, homeCategories } from '../../utils/emergency-data';

  const dispatch = createEventDispatcher();
  let checkedItems: Record<string, boolean> = {};

  function toggleCheck(id: string) {
    checkedItems[id] = !checkedItems[id];
    checkedItems = checkedItems;
  }
</script>

<div class="home-container">
  <!-- Emergency Contacts Bar -->
  <div class="contacts-bar">
    <div class="contacts-inner">
      <span class="contacts-label">Emergency</span>
      <div class="contacts-list">
        {#each emergencyContacts as contact}
          <a href="tel:{contact?.number}" class="contact-chip">
            <span class="chip-text">{contact?.label} <strong>{contact?.number}</strong></span>
          </a>
        {/each}
      </div>
    </div>
  </div>

  <!-- Hero Section -->
  <section class="hero">
    <div class="hero-icon">⚠️</div>
    <h1>Fraud Already Happened?</h1>
    <p class="hero-subtitle">Don't panic. Follow these steps immediately. Acting fast increases your chance of recovery.</p>
  </section>

  <!-- Category Selector -->
  <section class="section">
    <div class="section-header">
      <h2>What happened?</h2>
      <p>Select your situation</p>
    </div>
    <div class="category-grid">
      {#each homeCategories as category}
         <a
          href={`/emergency/${category.id}`}
          class="category-card"
        >
         
          <h3>{category?.title}</h3>
          <p>{category?.description}</p>
          <div class="category-keywords">
            {#each category?.keywords as keyword}
              <span class="keyword-tag">{keyword}</span>
            {/each}
          </div>
          <div class="category-arrow">→</div>
        </a>
      {/each}
    </div>
  </section>

  <!-- Universal First Steps -->
  <section class="section">
    <div class="section-header">
      <h2> Do This Right Now</h2>
      <p>These steps apply to every situation</p>
    </div>
    <div class="steps-list">
      {#each universalSteps as step, i}
        <div
          class="step-item"
          class:checked={checkedItems[step.id]}
          on:click={() => toggleCheck(step.id)}
          role="checkbox"
          aria-checked={checkedItems[step.id]}
          tabindex="0"
          on:keydown={(e) => e.key === 'Enter' && toggleCheck(step.id)}
        >
          <div class="step-number">{i + 1}</div>
          <div class="step-checkbox">
            {#if checkedItems[step.id]}
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
            {/if}
          </div>
          <span class="step-text">{step.text}</span>
        </div>
      {/each}
    </div>
  </section>

  <!-- Footer -->
  <footer class="home-footer">
    <p>📋 <strong>Not sure which category?</strong> Start with the universal steps above, then call <strong>1930</strong>.</p>
    <p class="footer-note">This guide is for general awareness. For case-specific legal advice, consult a lawyer.</p>
  </footer>
</div>

<style is:global>
  .home-container {
    max-width: 800px;
    margin: 0 auto;
  }

  .contacts-bar {
    top: 0;
    z-index: 100;
    background: white;
    color: black;
    border-bottom: 1px solid #1f2937;
  }

  .contacts-inner {
    padding: 10px 16px;
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }

  .contacts-label {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    opacity: 0.8;
    white-space: nowrap;
  }

  .contacts-list {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    
    flex: 1;
  }

  .contact-chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    background: rgba(255, 255, 255, 0.15);
    border:2px solid greenyellow;
    border-radius: 20px;
    color: black;
    text-decoration: none;
    font-size: 12px;
    transition: all 0.2s ease;
    white-space: nowrap;
  }

  .contact-chip:hover {
    background: rgba(255, 255, 255, 0.25);
    border-color: rgba(255, 255, 255, 0.5);
  }

  .chip-icon {
    font-size: 12px;
  }

  .chip-text {
    font-weight: 500;
  }

  .chip-text strong {
    font-weight: 700;
  }

  .hero {
    text-align: center;
    padding: 40px 20px 32px;
    border-bottom: 1px solid #f3f4f6;
  }

  .hero-icon {
    font-size: 40px;
    margin-bottom: 12px;
  }

  .hero h1 {
    font-size: 26px;
    font-weight: 700;
    color: #1f2937;
    margin: 0 0 8px;
    letter-spacing: -0.5px;
  }

  .hero-subtitle {
    font-size: 15px;
    color: #6b7280;
    max-width: 500px;
    margin: 0 auto;
    line-height: 1.6;
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
    font-size: 20px;
    font-weight: 600;
    color: #1f2937;
    margin: 0 0 4px;
  }

  .section-header p {
    font-size: 14px;
    color: #9ca3af;
    margin: 0;
  }

  .category-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 12px;
  }

  @media (min-width: 600px) {
    .category-grid {
      grid-template-columns: 1fr 1fr;
    }
  }

  .category-card {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    text-align: left;
    padding: 20px;
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    cursor: pointer;
    transition: all 0.2s ease;
    position: relative;
    font-family: inherit;
    width: 100%;
  }

  .category-card:hover {
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
    transform: translateY(-2px);
    border-color: #2563eb;
  }

  .category-card:active {
    transform: translateY(0);
  }


  .category-card h3 {
    font-size: 16px;
    font-weight: 600;
    color: #1f2937;
    margin: 0 0 6px;
    line-height: 1.3;
  }

  .category-card p {
    font-size: 13px;
    color: #6b7280;
    margin: 0 0 12px;
    line-height: 1.5;
  }

  .category-keywords {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-bottom: 12px;
  }

  .keyword-tag {
    font-size: 11px;
    padding: 2px 8px;
    background: #eff6ff;
    color: #1e40af;
    border-radius: 10px;
    font-weight: 500;
  }

  .category-arrow {
    position: absolute;
    top: 20px;
    right: 20px;
    font-size: 20px;
    color: #d1d5db;
    transition: transform 0.2s ease;
  }

  .category-card:hover .category-arrow {
    transform: translateX(4px);
    color: #2563eb;
  }

  .steps-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .step-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px 16px;
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.2s ease;
    user-select: none;
  }

  .step-item:hover {
    border-color: #d1d5db;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
  }

  .step-item.checked {
    background: #f9fafb;
    border-color: #d1d5db;
  }

  .step-item.checked .step-text {
    text-decoration: line-through;
    color: #9ca3af;
  }

  .step-number {
    width: 28px;
    height: 28px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #2563eb;
    color: #ffffff;
    border-radius: 50%;
    font-size: 13px;
    font-weight: 600;
    flex-shrink: 0;
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
    transition: all 0.2s ease;
  }

  .step-item.checked .step-checkbox {
    background: #2563eb;
    border-color: #2563eb;
    color: #ffffff;
  }

  .step-text {
    font-size: 14px;
    color: #1f2937;
    flex: 1;
    transition: all 0.2s ease;
  }

  .home-footer {
    padding: 32px 16px 48px;
    text-align: center;
  }

  .home-footer p {
    font-size: 14px;
    color: #6b7280;
    margin: 0 0 8px;
    line-height: 1.6;
  }

  .home-footer strong {
    color: #1f2937;
  }

  .footer-note {
    font-size: 12px !important;
    color: #9ca3af !important;
    font-style: italic;
    margin-top: 16px !important;
  }

  @media (max-width: 480px) {
    .contacts-inner {
      justify-content: center;
    }
    .contacts-label {
      width: 100%;
      text-align: center;
    }
    .contacts-list {
      justify-content: center;
    }
  }
</style>