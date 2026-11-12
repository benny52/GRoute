<script lang="ts">
  import type { Snippet } from 'svelte';
  import { helpClosed, setHelpClosed } from '../state.svelte';
  import Icon from './Icon.svelte';

  let { id, title, children }: { id: string; title: string; children: Snippet } = $props();

  let closed = $derived(helpClosed(id));
  function toggle() {
    closed = !closed;
    setHelpClosed(id, closed);
  }
</script>

<div class="hint-tools"><button class="ghost" aria-expanded={!closed} onclick={toggle}><Icon name="info" size={16} />Подсказка</button></div>
  {#if !closed}
  <section class="help">
    <Icon name="info" size={20} />
    <div class="grow">
      <b>{title}</b>
      <div class="text">{@render children()}</div>
    </div>
    <button
      class="icon"
      title="Свернуть подсказку" aria-label="Свернуть подсказку" onclick={toggle}><Icon name="x" size={16} /></button
    >
  </section>
{/if}

<style>
  .hint-tools { display: flex; justify-content: flex-end; }
  .help {
    display: flex;
    gap: 12px;
    align-items: flex-start;
    padding: 14px 16px;
    border-radius: var(--radius);
    background: var(--accent-soft);
    border: 1px solid color-mix(in srgb, var(--accent) 25%, transparent);
    user-select: text;
  }
  .help > :global(svg) { color: var(--accent); flex: none; margin-top: 1px; }
  .text { margin-top: 4px; color: var(--text); font-size: 13px; }
  .text :global(p) { margin: 0 0 6px; }
  .text :global(p:last-child) { margin: 0; }
  .text :global(ul) { margin: 4px 0 6px; padding-left: 18px; }
  .text :global(code) { font-family: var(--mono); font-size: 12px; }
</style>
