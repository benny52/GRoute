<script lang="ts">
  import { api, errText } from '../api';
  import AppPicker from './AppPicker.svelte';
  import Icon from './Icon.svelte';

  let { programs = $bindable<string[]>([]) }: { programs?: string[] } = $props();
  let picking = $state(false);
  let error = $state('');

  function add(path: string) {
    if (path && !programs.some((program) => program.toLowerCase() === path.toLowerCase())) programs = [...programs, path];
  }
  async function browse() {
    error = '';
    try { add(await api.BrowseExe()); }
    catch (e) { error = errText(e); }
  }
</script>

<div class="programs">
  <p>GRoute отправит распознанный BitTorrent напрямую. Участники раздачи увидят IP вашего подключения.</p>
  <b>Дополнительно по программе</b>
  <p class="muted small">У выбранных клиентов весь трафик пойдёт напрямую, включая зашифрованные раздачи и обращения к трекерам. Сайты в браузере продолжат открываться по своим правилам.</p>
  <div class="row wrap">
    <button onclick={() => (picking = true)}><Icon name="app" size={15} />Из запущенных…</button>
    <button onclick={browse}><Icon name="folder" size={15} />Обзор…</button>
  </div>
  {#each programs as path (path)}
    <div class="row">
      <span class="grow path">{path}</span>
      <button class="icon" title={`Убрать ${path}`} onclick={() => (programs = programs.filter((p) => p !== path))}><Icon name="x" size={14} /></button>
    </div>
  {/each}
  {#if error}<div class="note error small" role="alert">{error}</div>{/if}
</div>
{#if picking}
  <AppPicker chosen={programs} onpick={(a) => add(a.name)} onclose={() => (picking = false)} />
{/if}

<style>
  .programs { display: grid; gap: 8px; }
  .programs p { margin: 0; }
  .path { overflow-wrap: anywhere; }
</style>
