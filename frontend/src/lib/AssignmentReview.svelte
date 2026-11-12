<script lang="ts">
  import { onMount } from 'svelte';
  import { errText } from '../api';
  import { hide } from '../state.svelte';
  import AssignmentDialog from './AssignmentDialog.svelte';
  import { assignments, targetLabel, useTitle, useRole, type AssignmentPreview, type AssignmentRequest } from './assignments';

  let { request, title, confirmLabel, onclose, onapplied }: {
    request: AssignmentRequest;
    title: string;
    confirmLabel: string;
    onclose: () => void;
    onapplied: () => void;
  } = $props();
  let preview = $state<AssignmentPreview | null>(null);
  let busy = $state(false);
  let error = $state('');

  async function refresh() {
    busy = true;
    error = '';
    try {
      preview = await assignments.PreviewAssignments(request);
    } catch (e) {
      error = errText(e);
    } finally {
      busy = false;
    }
  }

  async function apply() {
    if (!preview || !preview.token || preview.blockers?.length || busy) return;
    busy = true;
    try {
      await assignments.ApplyAssignments(request, preview.token);
    } catch (e) {
      preview = null;
      error = errText(e);
      return;
    } finally {
      busy = false;
    }
    onapplied();
  }

  onMount(() => { void refresh(); });
  const chain = (ids: string[] | null) => ids?.length ? ids.map(targetLabel).join(' → ') : 'Нет';
  const routes = $derived((preview?.changes ?? []).filter((c) => !c.indirect && (c.kind === 'rule' || c.kind === 'default')));
  const profiles = $derived(new Set(routes.map((c) => c.rulesetId ?? c.rulesetName)).size);
  function count(kind: 'rule' | 'default', role?: 'primary' | 'fallback') {
    const keys = routes.filter((c) => c.kind === kind && (!role || c.role === role))
      .map((c) => JSON.stringify([c.rulesetId ?? c.rulesetName, c.ruleKey ?? c.name]));
    return new Set(keys).size;
  }
</script>

<AssignmentDialog {title} {onclose} locked={busy}>
    {#if error}<p class="note error" role="alert">{hide(error)}</p>{/if}
    {#if preview}
      {#if routes.length}
        <p class="small">Профилей — {profiles}. Правил — {count('rule')} (приоритетный сервер — {count('rule', 'primary')}, запасной — {count('rule', 'fallback')}).
          Маршрутов «Всё остальное» — {count('default')}.</p>
      {/if}
      {#if !preview.changes?.length}<p class="muted">Изменений нет.</p>{/if}
      {#each preview.changes ?? [] as change}
        <div class="change">
          <b>{useTitle(change)}</b>
          {#if useRole(change)}<div class="small muted">{useRole(change)}</div>{/if}
          {#if change.before?.length || change.after?.length}
            <dl><dt>Было</dt><dd>{chain(change.before)}</dd><dt>Станет</dt><dd>{chain(change.after)}</dd></dl>
          {/if}
          {#if change.detail}<div class="small">{hide(change.detail)}</div>{/if}
        </div>
      {/each}
      {#each preview.warnings ?? [] as note}<p class="note">{hide(note)}</p>{/each}
      {#each preview.blockers ?? [] as note}<p class="note error">{hide(note)}</p>{/each}
    {:else if busy}
      <p class="muted" role="status">Проверяем назначения…</p>
    {/if}
    <div class="actions">
      <button onclick={onclose} disabled={busy}>Отмена</button>
      {#if !preview || preview.blockers?.length}
        <button onclick={refresh} disabled={busy}>Обновить предпросмотр</button>
      {:else}
        <button class="primary" onclick={apply} disabled={busy || !preview.token || !preview.changes?.length}>{confirmLabel}</button>
      {/if}
    </div>
</AssignmentDialog>

<style>
  .change { padding: 10px 0; border-bottom: 1px solid var(--border); overflow-wrap: anywhere; }
  dl { display: grid; grid-template-columns: auto 1fr; gap: 3px 12px; margin: 6px 0 0; font-size: 13px; }
  dt { color: var(--muted); }
  dd { margin: 0; }
</style>
