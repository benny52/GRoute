<script lang="ts">
  import { onMount } from 'svelte';
  import { errText, type ProfileSummary } from '../api';
  import { hide, serverLabel } from '../state.svelte';
  import AssignmentDialog from './AssignmentDialog.svelte';
  import { assignments, useTitle, useRole, type AssignmentUse } from './assignments';

  let { profile, onclose }: { profile: ProfileSummary; onclose: () => void } = $props();
  let uses = $state<AssignmentUse[] | null>(null);
  let error = $state('');
  async function load() {
    error = '';
    uses = null;
    try {
      uses = (await assignments.ServerAssignments(profile.id)) ?? [];
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(() => { void load(); });
</script>

<AssignmentDialog title={`Где используется «${serverLabel(profile)}»`} {onclose}>
    {#if error}<p class="note error">{hide(error)}</p><button onclick={load}>Повторить</button>
    {:else if uses === null}<p class="muted" role="status">Проверяем все профили…</p>
    {:else}
      {#each uses as use}
        <div class="use">
          <b>{useTitle(use)}</b>
          {#if useRole(use)}<div class="small muted">{useRole(use)}</div>{/if}
          {#if use.detail}<div class="small">{hide(use.detail)}</div>{/if}
        </div>
      {:else}<p class="muted">Назначений нет.</p>{/each}
    {/if}
    <div class="actions"><button onclick={onclose}>Закрыть</button></div>
</AssignmentDialog>

<style>
  .use { border-bottom: 1px solid var(--border); padding: 8px 0; overflow-wrap: anywhere; }
</style>
