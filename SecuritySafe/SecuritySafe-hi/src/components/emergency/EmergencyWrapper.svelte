<script lang="ts">
  import EmergencyPage from './EmergencyPage.svelte';
  import type { EmergencyPage as EmergencyPageType } from '../../utils/emergency-data';

  export let page: EmergencyPageType;

  function handleBack() {
    // Use standard browser navigation since we are in Astro
    window.history.back();
  }
</script>


<EmergencyPage {page} on:back={handleBack} />