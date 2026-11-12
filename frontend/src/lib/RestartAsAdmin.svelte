<script lang="ts">
  import { api, errText } from '../api';
  import { hide } from '../state.svelte';
  import Icon from './Icon.svelte';

  let pending = $state(false);
  let error = $state('');

  async function restart() {
    if (pending) return;
    pending = true;
    error = '';
    try {
      await api.RestartAsAdmin();
    } catch (e) {
      error = errText(e);
      pending = false;
    }
  }
</script>

<div>
  <button class="primary" onclick={restart} disabled={pending}>
    <Icon name="shield" size={16} />{pending ? 'Перезапуск…' : 'Перезапустить от имени администратора'}
  </button>
  {#if error}<p class="note error" role="alert">{hide(error)}</p>{/if}
</div>
