<script lang="ts">
  import type { SubEntry, SubReport } from '../api';
  import { hide } from '../state.svelte';

  let { report, preview = false }: { report: SubReport; preview?: boolean } = $props();
  const profiles = $derived(report.profiles ?? []);
  const skipped = $derived(report.skipped ?? []);
  const duplicates = $derived(report.duplicates ?? []);
  const counts = $derived.by(() => {
    const byProtocol = new Map<string, number>();
    for (const p of profiles) byProtocol.set(p.protocol, (byProtocol.get(p.protocol) ?? 0) + 1);
    return [...byProtocol].map(([protocol, count]) => `${protocol} — ${count}`).join(', ');
  });
</script>

{#snippet label(entry: SubEntry)}
  {#if entry.name && entry.name !== 'Без имени'}{hide(entry.name)} · {/if}{entry.protocol}{#if entry.count} × {entry.count}{/if}
{/snippet}

<div class="report">
  <h3>{preview ? 'К сохранению' : 'Загружено серверов'} — {profiles.length}</h3>
  {#if counts}<div>{counts}</div>{/if}
  {#if profiles.length}<ul>{#each profiles as p}<li>{@render label(p)}</li>{/each}</ul>{/if}
  <h3>Пропущено — {skipped.reduce((n, e) => n + (e.count ?? 1), 0)}</h3>
  {#if skipped.length}
    <ul>{#each skipped as entry}<li>{@render label(entry)} · {entry.reason}</li>{/each}</ul>
  {/if}
  {#if duplicates.length}
    <h3>Объединено дублей — {duplicates.length}</h3>
    <ul>{#each duplicates as entry}<li>{@render label(entry)}</li>{/each}</ul>
  {/if}
  {#if report.warnings?.length}
    <h3>Предупреждения импорта</h3>
    <ul>{#each report.warnings as w}<li>{hide(w)}</li>{/each}</ul>
  {/if}
  {#if report.partial}<p class="muted">Снимок последней загрузки недоступен. Для пропущенных записей сохранились только итоги.</p>{/if}
</div>

<style>
  .report { margin-block: 6px; padding: 8px 12px; border-left: 2px solid var(--border); font-size: 13px; overflow-wrap: anywhere; }
  h3 { font-size: 13px; margin: 8px 0 3px; }
  h3:first-child { margin-top: 0; }
  ul { max-height: 220px; overflow: auto; margin: 2px 0 6px; padding-left: 20px; }
</style>
