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

<div class="emergency-wrapper">
  <!-- Top Nav Bar with Back Button -->
  <div class="emergency-nav-strip">
    <div class="emergency-nav-inner">
      <a href="/" class="back-link">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="15 18 9 12 15 6"/>
        </svg>
        <span>Back to Home</span>
      </a>
    </div>
  </div>

  <!-- Official Helplines Header -->
  <div class="emergency-hotline-strip">
    <div class="hotline-strip-inner">
      <div class="hotline-brand-tag">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <span>Official Cybercrime & Banking Helplines</span>
      </div>
      <div class="hotline-chips">
        {#each emergencyContacts as contact}
          <a href="tel:{contact?.number}" class="hotline-chip">
            <span class="chip-dot"></span>
            <span class="chip-name">{contact?.label}</span>
            <strong class="chip-num">{contact?.number}</strong>
          </a>
        {/each}
      </div>
    </div>
  </div>

  <div class="home-container">
    <!-- Clean Emergency Hero -->
    <section class="emergency-hero">
      <div class="hero-alert-badge">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <span>Incident Guidance & Support</span>
      </div>
      <h1 class="emergency-title">What to do if you suspect fraud</h1>
      <p class="emergency-subtitle">
        Stay calm and take action methodically. Following these established containment steps helps protect your accounts, freeze unauthorized activity, and file official complaints.
      </p>
    </section>

    <!-- Universal Immediate Steps (Golden Hour Protocol) -->
    <section class="emergency-section">
      <div class="section-header">
        <span class="section-eyebrow">STEP 1 • ALL INCIDENTS</span>
        <h2 class="section-title">Essential Immediate Actions</h2>
        <p class="section-desc">Perform these actions immediately regardless of which fraud type you encountered:</p>
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
            <div class="step-num-badge">{i + 1}</div>
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

    <!-- Category Selector Grid -->
    <section class="emergency-section">
      <div class="section-header">
        <span class="section-eyebrow">STEP 2 • SPECIFIC RECOVERY</span>
        <h2 class="section-title">Select What Happened</h2>
        <p class="section-desc">Choose your scenario below for step-by-step containment procedures:</p>
      </div>
      <div class="category-grid">
        {#each homeCategories as category}
          <a href={`/emergency/${category.id}`} class="category-card">
            <div class="category-card-top">
              <h3 class="category-heading">{category?.title}</h3>
              <div class="category-arrow">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                  <polyline points="9 18 15 12 9 6"/>
                </svg>
              </div>
            </div>
            <p class="category-desc">{category?.description}</p>
            <div class="category-keywords">
              {#each category?.keywords as keyword}
                <span class="keyword-tag">{keyword}</span>
              {/each}
            </div>
          </a>
        {/each}
      </div>
    </section>

    <!-- Emergency Bottom Notice -->
    <footer class="emergency-footer-card">
      <div class="notice-inner">
        <h4>Need Instant Guidance?</h4>
        <p>If you're unsure which category fits, immediately dial the National Helpline <strong>1930</strong> or register an online formal cyber complaint at <strong>cybercrime.gov.in</strong>.</p>
      </div>
    </footer>
  </div>
</div>

<style is:global>
  .emergency-wrapper {
    min-height: 100vh;
    background: #FFFFFF;
    color: #0F172A;
    font-family: inherit;
  }

  /* Back Nav Strip */
  .emergency-nav-strip {
    padding: 16px 24px 8px;
    background: #FFFFFF;
  }
  .emergency-nav-inner {
    max-width: 1000px;
    margin: 0 auto;
  }
  .back-link {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    color: #475569;
    font-size: 13.5px;
    font-weight: 600;
    text-decoration: none;
    padding: 6px 12px;
    border-radius: 8px;
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    transition: all 0.2s ease;
  }
  .back-link:hover {
    color: #0F172A;
    background: #F1F5F9;
    border-color: #CBD5E1;
  }

  /* Hotline Strip */
  .emergency-hotline-strip {
    background: #F8FAFC;
    border-top: 1px solid #F1F5F9;
    border-bottom: 1px solid #E2E8F0;
    padding: 12px 24px;
    position: sticky;
    top: 64px;
    z-index: 30;
  }
  .hotline-strip-inner {
    max-width: 1000px;
    margin: 0 auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
  }
  .hotline-brand-tag {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: 11.5px;
    font-weight: 700;
    letter-spacing: 0.06em;
    color: #334155;
    text-transform: uppercase;
  }
  .hotline-brand-tag svg {
    color: #059669;
  }

  .hotline-chips {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
  }
  .hotline-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 12px;
    background: #FFFFFF;
    border: 1px solid #CBD5E1;
    border-radius: 100px;
    text-decoration: none;
    font-size: 12.5px;
    color: #1E293B;
    transition: all 0.2s ease;
  }
  .hotline-chip:hover {
    background: #0F172A;
    border-color: #0F172A;
    color: #FFFFFF;
  }
  .hotline-chip:hover .chip-num {
    color: #FFFFFF;
  }
  .chip-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: #059669;
  }
  .hotline-chip:hover .chip-dot {
    background: #34D399;
  }
  .chip-name {
    font-weight: 500;
    color: #475569;
  }
  .hotline-chip:hover .chip-name {
    color: #FFFFFF;
  }
  .chip-num {
    font-weight: 800;
    color: #0F172A;
  }

  /* Main Container */
  .home-container {
    max-width: 920px;
    margin: 0 auto;
    padding: 36px 24px 80px;
  }

  /* Emergency Hero */
  .emergency-hero {
    text-align: center;
    padding: 16px 0 36px;
    border-bottom: 1px solid #E2E8F0;
  }
  .hero-alert-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    background: #ECFDF5;
    border: 1px solid #A7F3D0;
    color: #065F46;
    border-radius: 100px;
    font-size: 11.5px;
    font-weight: 700;
    letter-spacing: 0.05em;
    margin-bottom: 16px;
  }
  .emergency-title {
    font-size: clamp(1.8rem, 4vw, 2.6rem);
    font-weight: 800;
    color: #0F172A;
    letter-spacing: -0.03em;
    margin: 0 0 12px;
  }
  .emergency-subtitle {
    font-size: 15px;
    color: #475569;
    max-width: 640px;
    margin: 0 auto;
    line-height: 1.6;
  }

  /* Sections */
  .emergency-section {
    padding: 40px 0;
    border-bottom: 1px solid #E2E8F0;
  }
  .section-header {
    margin-bottom: 24px;
  }
  .section-eyebrow {
    display: inline-block;
    font-size: 11px;
    font-weight: 800;
    color: #2563EB;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 6px;
  }
  .section-title {
    font-size: 20px;
    font-weight: 800;
    color: #0F172A;
    letter-spacing: -0.02em;
    margin: 0 0 6px;
  }
  .section-desc {
    font-size: 14px;
    color: #64748B;
    margin: 0;
  }

  /* Universal Step Checklist */
  .steps-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .step-item {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 16px 20px;
    background: #F8FAFC;
    border: 1.5px solid #E2E8F0;
    border-radius: 12px;
    cursor: pointer;
    transition: all 0.2s ease;
    user-select: none;
  }
  .step-item:hover {
    border-color: #CBD5E1;
    background: #FFFFFF;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
  }
  .step-item.checked {
    background: #F1F5F9;
    border-color: #CBD5E1;
  }
  .step-item.checked .step-text {
    text-decoration: line-through;
    color: #94A3B8;
  }
  .step-num-badge {
    width: 26px;
    height: 26px;
    border-radius: 50%;
    background: #0F172A;
    color: #FFFFFF;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    font-weight: 700;
    flex-shrink: 0;
  }
  .step-checkbox {
    width: 20px;
    height: 20px;
    border: 2px solid #CBD5E1;
    border-radius: 6px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    background: #FFFFFF;
    transition: all 0.2s ease;
  }
  .step-item.checked .step-checkbox {
    background: #10B981;
    border-color: #10B981;
    color: #FFFFFF;
  }
  .step-text {
    font-size: 14.5px;
    font-weight: 500;
    color: #1E293B;
    flex: 1;
    line-height: 1.45;
  }

  /* Scenario Cards */
  .category-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }
  .category-card {
    display: flex;
    flex-direction: column;
    padding: 22px;
    background: #FFFFFF;
    border: 1.5px solid #E2E8F0;
    border-radius: 14px;
    text-decoration: none;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
  }
  .category-card:hover {
    border-color: #0F172A;
    transform: translateY(-2px);
    box-shadow: 0 10px 24px rgba(0, 0, 0, 0.05);
  }
  .category-card-top {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
    margin-bottom: 8px;
  }
  .category-heading {
    font-size: 16px;
    font-weight: 700;
    color: #0F172A;
    margin: 0;
    line-height: 1.35;
  }
  .category-arrow {
    color: #94A3B8;
    transition: transform 0.2s ease, color 0.2s ease;
  }
  .category-card:hover .category-arrow {
    color: #0F172A;
    transform: translateX(3px);
  }
  .category-desc {
    font-size: 13px;
    color: #64748B;
    line-height: 1.5;
    margin: 0 0 14px;
    flex: 1;
  }
  .category-keywords {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .keyword-tag {
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    background: #F1F5F9;
    color: #475569;
    border-radius: 4px;
  }

  /* Bottom Card */
  .emergency-footer-card {
    margin-top: 40px;
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 14px;
    padding: 24px;
    text-align: center;
  }
  .notice-inner h4 {
    font-size: 16px;
    font-weight: 700;
    color: #0F172A;
    margin: 0 0 6px;
  }
  .notice-inner p {
    font-size: 13.5px;
    color: #64748B;
    margin: 0;
    line-height: 1.5;
  }

  @media (max-width: 640px) {
    .emergency-hotline-strip { padding: 10px 16px; }
    .hotline-strip-inner { flex-direction: column; align-items: flex-start; gap: 8px; }
    .home-container { padding: 24px 16px 60px; }
    .category-grid { grid-template-columns: 1fr; }
  }
</style>