<script lang="ts">
  // The <option>s of a target select (rule, «Всё остальное», fallbacks,
  // proxies, the main server): the servers, then the server groups. A
  // current value outside these lists (built-in bridge or deleted target)
  // keeps its own option.
  import type { GroupView } from '../api';
  import { ui, hide, profileName, serverSections } from '../state.svelte';

  let { exclude = () => false, current = '' }: { exclude?: (id: string) => boolean; current?: string } = $props();

  const sections = $derived(serverSections().map((s) => ({ ...s, list: s.list.filter((p) => !exclude(p.id)) })).filter((s) => s.list.length));
  const groups = $derived(ui.groups.filter((g) => !exclude(g.id)));
  const unlisted = $derived(!!current && !exclude(current) && !ui.profiles.some((p) => p.id === current) && !ui.groups.some((g) => g.id === current));
  const count = (g: GroupView) => g.members.length - g.missing;
</script>

{#each sections as sec (sec.key)}
  {#if sec.title}
    <optgroup label={sec.title}>
      {#each sec.list as p (p.id)}<option value={p.id}>{hide(p.name)}{p.missing ? ' — нет в подписке' : ''}</option>{/each}
    </optgroup>
  {:else}
    {#each sec.list as p (p.id)}<option value={p.id}>{hide(p.name)}{p.sourceName ? ` · ${hide(p.sourceName)}` : ''}{p.missing ? ' — нет в подписке' : ''}</option>{/each}
  {/if}
{/each}
{#if groups.length}
  <optgroup label="Группы серверов">
    {#each groups as g (g.id)}<option value={g.id}>«{hide(g.name)}» (группа · {count(g)})</option>{/each}
  </optgroup>
{/if}
{#if unlisted}<option value={current}>{profileName(current)}</option>{/if}
