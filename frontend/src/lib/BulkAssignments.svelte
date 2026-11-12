<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errText, toLists, type Settings, type RulesetView } from '../api';
  import { hide, ui } from '../state.svelte';
  import { ruleTitle } from '../ruletitle';
  import { mainOption, targetLabel, type AssignmentRequest, type AssignmentRow, type Role } from './assignments';
  import AssignmentReview from './AssignmentReview.svelte';
  import AssignmentDialog from './AssignmentDialog.svelte';
  import TargetOptions from './TargetOptions.svelte';

  let { currentId, onclose, onapplied }: { currentId: string | null; onclose: () => void; onapplied: () => void } = $props();
  type Row = { key: string; ref: AssignmentRow; title: string; action: string; disabled: boolean; primary: string; fallback: string[] };
  type Section = { profile: RulesetView; rows: Row[] };
  let sections = $state<Section[]>([]);
  let openedId = '';
  let scope = $state<'current' | 'all'>('current');
  let operation = $state<'set' | 'replace'>('set');
  let role = $state<Role>('primary');
  let source = $state('');
  let target = $state('');
  let fallback = $state<string[]>([]);
  let picks = $state<Record<string, boolean>>({});
  let review = $state<AssignmentRequest | null>(null);
  let error = $state('');
  let loading = $state(false);
  let multiple = $state(false);

  function rowsFor(profile: RulesetView, config: Settings): Row[] {
    const counts = new Map<string, number>();
    for (const r of config.rules ?? []) {
      if (r.id) counts.set(r.id, (counts.get(r.id) ?? 0) + 1);
    }
    const rows: Row[] = (config.rules ?? []).map((r, index) => ({
      key: JSON.stringify([profile.id, index]),
      ref: { rulesetId: profile.id, ruleId: r.id ?? '', isDefault: false,
        ...(!r.id || (counts.get(r.id) ?? 0) > 1 ? { index, revision: (config.rev ?? 0) + '/' + (config.editRev ?? 0) } : {}) },
      title: ruleTitle(toLists(r)), action: r.action, disabled: r.enabled === false,
      primary: r.profile ?? '', fallback: r.fallback ?? [],
    }));
    rows.push({
      key: JSON.stringify([profile.id, 'default']), ref: { rulesetId: profile.id, ruleId: '', isDefault: true },
      title: 'Всё остальное', action: config.defaultAction, disabled: false,
      primary: config.defaultProfile ?? '', fallback: config.defaultFallback ?? [],
    });
    return rows;
  }

  // Open the profile being viewed and keep its ID while the dialog is open.
  // A scope change always starts a fresh selection.
  let seq = 0;
  async function loadScope(next: 'current' | 'all', initial = false) {
    const n = ++seq;
    scope = next;
    picks = {};
    sections = [];
    error = '';
    loading = true;
    try {
      const view = await api.Rulesets();
      if (n !== seq) return;
      if (view.error) throw new Error(view.error);
      if (initial) openedId = currentId ?? view.active;
      multiple = view.list.length > 1;
      const profiles = next === 'all' ? view.list : view.list.filter((p) => p.id === openedId);
      if (!profiles.length) throw new Error('Профиль правил больше недоступен. Откройте окно заново.');
      const result = await Promise.all(profiles.map(async (profile) => {
        if (profile.error || profile.newer) throw new Error('Профиль «' + profile.name + '» недоступен для изменения. ' + (profile.error ?? ''));
        const config = profile.id ? await api.RulesetSettings(profile.id) : await api.Settings();
        if (!profile.id && config.ruleset && config.ruleset !== view.token) throw new Error('Профиль правил сменился. Откройте окно заново.');
        return { profile, rows: rowsFor(profile, config) };
      }));
      if (n === seq) sections = result;
    } catch (e) {
      if (n === seq) error = errText(e);
    } finally {
      if (n === seq) loading = false;
    }
  }

  onMount(() => { void loadScope('current', true); });

  function eligible(row: Row) {
    if (row.action !== 'tunnel') return false;
    if (operation !== 'replace') return true;
    return (role !== 'fallback' && row.primary === source) || (role !== 'primary' && row.fallback.includes(source));
  }

  const available = $derived(sections.flatMap((s) => s.rows).filter(eligible));
  const selected = $derived(available.filter((r) => picks[r.key]));
  const missing = $derived([...new Set(sections.flatMap((s) => s.rows.flatMap((r) => [r.primary, ...r.fallback])))]
    .filter((id) => id && !ui.groups.some((g) => g.id === id) && !ui.profiles.some((p) => p.id === id)));

  function mode(next: 'set' | 'replace') {
    operation = next;
    if (role === 'both' && next === 'set') role = 'primary';
    picks = {};
  }

  function move(index: number, by: number) {
    const next = [...fallback];
    [next[index], next[index + by]] = [next[index + by], next[index]];
    fallback = next;
  }

  function preview() {
    review = {
      operation, role, rows: selected.map((r) => ({ ...r.ref })),
      ...(operation === 'replace' ? { source, target } : role === 'primary' ? { target } : { fallback: [...fallback] }),
    };
  }
</script>

{#if review}
  <AssignmentReview request={review} title="Предпросмотр назначений" confirmLabel="Применить" onclose={() => (review = null)} {onapplied} />
{:else}
  <AssignmentDialog wide title="Групповое изменение" {onclose}>
      <div class="fields">
        <label>Операция
          <select value={operation} onchange={(e) => mode(e.currentTarget.value as typeof operation)}>
            <option value="set">Назначить выбранным строкам</option><option value="replace">Заменить конкретное назначение</option>
          </select>
        </label>
        <label>Профили правил
          <select value={scope} onchange={(e) => loadScope(e.currentTarget.value as typeof scope)}>
            <option value="current">Текущий профиль</option><option value="all" disabled={!multiple}>Все профили</option>
          </select>
        </label>
        <label>Что изменить
          <select bind:value={role}>
            <option value="primary">Приоритетный сервер</option><option value="fallback">Запасной сервер</option>
            {#if operation === 'replace'}<option value="both">Обе роли</option>{/if}
          </select>
        </label>
        {#if operation === 'replace'}
          <label>Что заменить
            <select bind:value={source}><option value="">{mainOption()}</option><TargetOptions />
              {#each missing as id}<option value={id}>Удалённое назначение · {id}</option>{/each}
            </select>
          </label>
        {/if}
        {#if operation === 'replace' || role === 'primary'}
          <label>{operation === 'replace' ? 'На что заменить' : 'Приоритетный сервер'}
            <select bind:value={target}><option value="">{mainOption()}</option><TargetOptions /></select>
          </label>
        {:else}
          <div class="reserves">
            <label>Запасной сервер
              <select value="__add" onchange={(e) => {
                const id = e.currentTarget.value;
                e.currentTarget.value = '__add';
                if (!fallback.includes(id)) fallback = [...fallback, id];
              }}>
                <option value="__add" disabled>Добавить запасной сервер</option>
                {#if !fallback.includes('')}<option value="">{mainOption()}</option>{/if}
                <TargetOptions exclude={(id) => fallback.includes(id)} />
              </select>
            </label>
            {#each fallback as id, i (id)}
              <div class="reserve"><span>{i + 1}. {targetLabel(id)}</span>
                <button aria-label="Выше" disabled={i === 0} onclick={() => move(i, -1)}>↑</button>
                <button aria-label="Ниже" disabled={i === fallback.length - 1} onclick={() => move(i, 1)}>↓</button>
                <button aria-label="Убрать" onclick={() => (fallback = fallback.filter((v) => v !== id))}>×</button>
              </div>
            {:else}<span class="small muted">Пустой список очистит запасные серверы у отмеченных строк.</span>{/each}
          </div>
        {/if}
      </div>
      {#if error}<p class="note error">{hide(error)}</p><button onclick={() => loadScope(scope)}>Обновить список</button>
      {:else if loading}<p class="muted" role="status">Загружаем правила…</p>
      {:else}
        <label class="pick"><input type="checkbox" disabled={!available.length}
          checked={available.length > 0 && selected.length === available.length}
          indeterminate={selected.length > 0 && selected.length < available.length}
          onchange={(e) => { picks = e.currentTarget.checked ? Object.fromEntries(available.map((r) => [r.key, true])) : {}; }} />
          Выбрать все доступные строки
        </label>
        {#each sections as section (section.profile.id)}
          <h3>{hide(section.profile.name)}{section.profile.active ? '' : ' · неактивный профиль'}</h3>
          {#each section.rows as row (row.key)}
            <label class="pick line" class:unavailable={!eligible(row)}>
              <input type="checkbox" disabled={!eligible(row)} checked={eligible(row) && !!picks[row.key]}
                onchange={(e) => (picks[row.key] = e.currentTarget.checked)} />
              <span><b>{row.title}</b>{row.disabled ? ' · выключено' : ''}
                <small>{#if row.action === 'tunnel'}
                  Приоритетный сервер — {targetLabel(row.primary)} · Запасные — {row.fallback.map(targetLabel).join(' → ') || 'нет'}
                {:else}{row.action === 'direct' ? 'Напрямую' : 'Заблокировать'}{/if}</small>
              </span>
            </label>
          {/each}
        {/each}
      {/if}
      <div class="actions">
        <button onclick={onclose}>Отмена</button>
        <button class="primary" disabled={!selected.length || loading} onclick={preview}>Предпросмотр ({selected.length})</button>
      </div>
  </AssignmentDialog>
{/if}

<style>
  .fields { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin: 14px 0; }
  .fields label { display: grid; gap: 4px; font-size: 13px; }
  .fields select { min-width: 0; width: 100%; }
  .reserve, .pick { display: flex; align-items: center; gap: 8px; }
  .reserve { margin: 4px 0; }
  .reserve span { flex: 1; overflow-wrap: anywhere; }
  .reserve button { padding: 3px 7px; }
  .line { padding: 8px 0; border-bottom: 1px solid var(--border); }
  .unavailable { opacity: 0.6; }
  small { display: block; color: var(--muted); overflow-wrap: anywhere; }
  h3 { margin: 14px 0 4px; }
</style>
