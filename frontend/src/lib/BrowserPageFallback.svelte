<script lang="ts">
  import { api, errText } from '../api';
  import Icon from './Icon.svelte';

  let { page }: { page: string } = $props();
  let note = $state('');

  async function copy() {
    try {
      await api.CopyText(page);
      note = 'Адрес скопирован.';
    } catch (e) {
      note = errText(e);
    }
  }
</script>

<div class="note warn small">
  <p>Чтобы открыть страницу вручную, вставьте этот адрес в адресную строку браузера и нажмите Enter.</p>
  <div class="row">
    <code>{page}</code>
    <button onclick={copy}><Icon name="copy" size={15} /> Скопировать адрес</button>
  </div>
  {#if note}<span role="status">{note}</span>{/if}
</div>

<style>
  .row { flex-wrap: wrap; }
  code { user-select: all; overflow-wrap: anywhere; }
</style>
