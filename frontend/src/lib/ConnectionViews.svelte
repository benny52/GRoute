<script lang="ts">
  import Connections from './Connections.svelte';
  import LiveTraffic from './LiveTraffic.svelte';
  import { setConnNav } from './ConnMenu.svelte';

  let { go }: { go: (id: string) => void } = $props();
  // svelte-ignore state_referenced_locally
  setConnNav(go);

  const views = [
    { id: 'map', label: 'Карта' },
    { id: 'table', label: 'Таблица' },
    { id: 'details', label: 'Подробный список' },
  ] as const;
  let view = $state<(typeof views)[number]['id']>('map');
</script>

<div class="views" class:details={view === 'details'}>
  <header>
    <h1>Соединения</h1>
    <div class="seg" role="group" aria-label="Вид соединений">
      {#each views as tab}
        <button class:on={view === tab.id} aria-pressed={view === tab.id} onclick={() => view = tab.id}>{tab.label}</button>
      {/each}
    </div>
  </header>
  {#if view === 'details'}
    <Connections />
  {:else}
    <LiveTraffic mapView={view === 'map'} />
  {/if}
</div>

<style>
  .views { display: flex; flex-direction: column; gap: 12px; }
  .details { height: 100%; }
  header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; }
</style>
