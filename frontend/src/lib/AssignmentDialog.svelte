<script lang="ts">
  import { onMount, type Snippet } from 'svelte';

  let { title, onclose, locked = false, wide = false, children }: {
    title: string; onclose: () => void; locked?: boolean; wide?: boolean; children: Snippet;
  } = $props();

  let dialog: HTMLDialogElement;
  onMount(() => {
    const element = dialog;
    element.showModal();
    return () => element.close();
  });
</script>

<dialog class="dialog" class:wide bind:this={dialog} aria-label={title}
  oncancel={(e) => { e.preventDefault(); if (!locked) onclose(); }}>
  <h2>{title}</h2>
  {@render children()}
</dialog>

<style>
  dialog { margin: auto; color: var(--text); }
  dialog.wide { width: min(740px, 94vw); }
  dialog::backdrop { background: rgba(8, 10, 16, 0.5); }
</style>
