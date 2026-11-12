<script lang="ts">
  import { onMount } from 'svelte';
  import { api, cleanFallback, errText, toLists, type Settings, type RulesetView } from '../api';
  import { hide, ui } from '../state.svelte';
  import { ruleTitle } from '../ruletitle';
  import { assignments, mainOption, targetLabel, type AssignmentRequest, type AssignmentRow, type Role } from './assignments';
  import AssignmentDialog from './AssignmentDialog.svelte';
  import TargetOptions from './TargetOptions.svelte';
  import FallbackPicker from './FallbackPicker.svelte';

  let { currentId, onclose, onapplied }: { currentId: string | null; onclose: () => void; onapplied: () => void } = $props();

  type Chain = { primary: string; fallback: string[] };
  type Row = Chain & { key: string; ref: AssignmentRow; title: string; action: string; disabled: boolean };
  type Section = { profile: RulesetView; rows: Row[] };

  let openedId = $state('');
  let scope = $state<'current' | 'all'>('current');
  let sections = $state<Section[]>([]);
  let multiple = $state(false);
  let loading = $state(false);
  let saving = $state(false);
  let error = $state('');
  let loadError = $state(false);
  let operation = $state<'set' | 'replace'>('set');
  let picks = $state<Record<string, boolean>>({});
  let overrides = $state<Record<string, Partial<Chain>>>({});
  let expanded = $state<Record<string, boolean>>({});
  let commonPrimary = $state<string | undefined>();
  let commonFallback = $state<string[] | undefined>();
  let source = $state('');
  let target = $state('');
  let role = $state<Role>('both');

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

  async function loadScope(next: typeof scope, refresh = false) {
    loading = true;
    error = '';
    loadError = false;
    scope = next;
    try {
      const view = await api.Rulesets();
      if (view.error) throw new Error(view.error);
      if (!sections.length) openedId = currentId ?? view.active;
      multiple = view.list.length > 1;
      const profiles = next === 'all' ? view.list : view.list.filter((p) => p.id === openedId);
      if (!profiles.length) throw new Error('Профиль правил больше недоступен. Откройте окно заново.');
      const result = await Promise.all(profiles.map(async (profile) => {
        if (profile.error || profile.newer) throw new Error('Профиль «' + profile.name + '» недоступен для изменения. ' + (profile.error ?? ''));
        const existing = sections.find((s) => s.profile.id === profile.id);
        if (existing && !refresh) return existing;
        const config = profile.id ? await api.RulesetSettings(profile.id) : await api.Settings();
        if (!profile.id && config.ruleset && config.ruleset !== view.token) throw new Error('Профиль правил сменился. Откройте окно заново.');
        return { profile, rows: rowsFor(profile, config) };
      }));
      sections = next === 'all' || refresh ? result : [...result, ...sections.filter((s) => s.profile.id !== openedId)];
      if (refresh) {
        picks = {};
        overrides = {};
      }
    } catch (e) {
      error = errText(e);
      loadError = true;
    } finally {
      loading = false;
    }
  }

  onMount(() => { void loadScope('current'); });

  const visible = $derived(sections.filter((s) => scope === 'all' || s.profile.id === openedId));
  const rows = $derived(visible.flatMap((s) => s.rows));
  const missing = $derived([...new Set(rows.flatMap((r) => [r.primary, ...r.fallback]))]
    .filter((id) => id && !ui.groups.some((g) => g.id === id) && !ui.profiles.some((p) => p.id === id)));

  function eligible(row: Row) {
    if (row.action !== 'tunnel') return false;
    if (operation === 'set') return true;
    return (role !== 'fallback' && row.primary === source) || (role !== 'primary' && row.fallback.includes(source));
  }

  const available = $derived(rows.filter(eligible));
  const selected = $derived(available.filter((r) => picks[r.key]));

  function propose(row: Row): Chain {
    if (!picks[row.key] || !eligible(row)) return row;
    let primary: string;
    let fallback: string[];
    if (operation === 'replace') {
      primary = role !== 'fallback' && row.primary === source ? target : row.primary;
      fallback = role === 'primary' ? row.fallback : row.fallback.map((id) => id === source ? target : id);
    } else {
      primary = overrides[row.key]?.primary ?? commonPrimary ?? row.primary;
      fallback = overrides[row.key]?.fallback ?? commonFallback ?? row.fallback;
    }
    if (primary === row.primary && sameOrder(row.fallback, fallback)) return row;
    return { primary, fallback: cleanFallback(fallback, primary) };
  }

  function sameOrder(a: string[], b: string[]) {
    return a.length === b.length && a.every((id, i) => id === b[i]);
  }

  const edits = $derived(selected.flatMap((row) => {
    const after = propose(row);
    if (after.primary === row.primary && sameOrder(after.fallback, row.fallback)) return [];
    return [{ row: row.ref, ...after, beforePrimary: row.primary, beforeFallback: row.fallback }];
  }));

  function changeCommon(field: keyof Chain) {
    for (const row of selected) {
      if (overrides[row.key]) delete overrides[row.key][field];
    }
    error = '';
  }

  function changeRow(row: Row, change: Partial<Chain>) {
    picks[row.key] = true;
    overrides[row.key] = { ...overrides[row.key], ...change };
    error = '';
  }

  function chainLabel(chain: Chain) {
    return [chain.primary, ...chain.fallback].map(targetLabel).join(' → ');
  }

  async function save() {
    if (saving || !edits.length) return;
    const request: AssignmentRequest = { operation: 'edit', edits: $state.snapshot(edits) };
    saving = true;
    error = '';
    try {
      const preview = await assignments.PreviewAssignments(request);
      if (preview.blockers?.length) throw new Error(preview.blockers.join(' '));
      if (!preview.token || !preview.changes?.length) throw new Error('Назначения изменились. Загрузите правила заново.');
      await assignments.ApplyAssignments(request, preview.token);
    } catch (e) {
      error = errText(e);
      return;
    } finally {
      saving = false;
    }
    onapplied();
  }
</script>

<AssignmentDialog wide title="Групповое изменение" {onclose} locked={saving}>
  <fieldset disabled={loading || saving}>
    <div class="fields">
      <label>Профили правил
        <select value={scope} onchange={(e) => loadScope(e.currentTarget.value as typeof scope)}>
          <option value="current">Текущий профиль</option><option value="all" disabled={!multiple}>Все профили</option>
        </select>
      </label>
      <label>Операция
        <select value={operation} onchange={(e) => { operation = e.currentTarget.value as typeof operation; picks = {}; error = ''; }}>
          <option value="set">Назначить серверы</option><option value="replace">Заменить конкретное назначение</option>
        </select>
      </label>
    </div>
    {#if operation === 'set'}
      <div class="common">
        <h3>Для отмеченных правил</h3>
        <label class="field">Приоритетный сервер
          <select value={commonPrimary ?? '__keep'} onchange={(e) => {
            commonPrimary = e.currentTarget.value === '__keep' ? undefined : e.currentTarget.value;
            changeCommon('primary');
          }}>
            <option value="__keep">Оставить у каждого свой</option>
            <option value="">{mainOption()}</option><TargetOptions />
          </select>
        </label>
        <label class="pick"><input type="checkbox" checked={commonFallback !== undefined}
          onchange={(e) => { commonFallback = e.currentTarget.checked ? [] : undefined; changeCommon('fallback'); }} />
          Изменить запасные серверы</label>
        {#if commonFallback !== undefined}
          <FallbackPicker compact primary={commonPrimary} value={commonFallback} onchange={(v) => { commonFallback = v; changeCommon('fallback'); }} />
          {#if !commonFallback.length}<small>У отмеченных правил не будет запасных серверов.</small>{/if}
        {/if}
      </div>
    {:else}
      <div class="fields">
        <label>Что заменить
          <select bind:value={source}><option value="">{mainOption()}</option><TargetOptions />
            {#each missing as id}<option value={id}>Удалённое назначение · {hide(id)}</option>{/each}
          </select>
        </label>
        <label>На что заменить
          <select bind:value={target}><option value="">{mainOption()}</option><TargetOptions /></select>
        </label>
        <label>Что изменить
          <select bind:value={role}>
            <option value="both">Обе роли</option><option value="primary">Приоритетный сервер</option><option value="fallback">Запасной сервер</option>
          </select>
        </label>
      </div>
    {/if}
    {#if loading}<p class="muted" role="status">Загружаем правила…</p>
    {:else if !loadError}
      <small class="legend">В цепочке первым указан приоритетный сервер, за ним — запасные по порядку.</small>
      <label class="pick select-all"><input type="checkbox" disabled={!available.length}
        checked={available.length > 0 && selected.length === available.length}
        indeterminate={selected.length > 0 && selected.length < available.length}
        onchange={(e) => { for (const row of available) picks[row.key] = e.currentTarget.checked; }} />
        Выбрать все доступные VPN-правила ({available.length})
      </label>
      {#each visible as section (section.profile.id)}
        <h3>{hide(section.profile.name)}{section.profile.active ? '' : ' · неактивный профиль'}</h3>
        {#each section.rows as row (row.key)}
          {@const after = propose(row)}
          {@const changed = after.primary !== row.primary || !sameOrder(after.fallback, row.fallback)}
          <div class="line" class:unavailable={!eligible(row)}>
            <label class="pick"><input type="checkbox" disabled={!eligible(row)} checked={eligible(row) && !!picks[row.key]}
              onchange={(e) => (picks[row.key] = e.currentTarget.checked)} />
              <b>{row.title}</b>{row.disabled ? ' · выключено' : ''}
            </label>
            {#if row.action === 'tunnel'}
              <div class="chain">
                {#if changed}<small>Было · {chainLabel(row)}</small>{/if}
                <span>{changed ? 'Станет' : 'Назначение'} · {chainLabel(after)}</span>
              </div>
              {#if operation === 'set'}
                <details ontoggle={(e) => (expanded[row.key] = e.currentTarget.open)}>
                  <summary>Изменить для этого правила</summary>
                  {#if expanded[row.key]}
                    <label class="field">Приоритетный сервер
                      <select value={after.primary} onchange={(e) => changeRow(row, { primary: e.currentTarget.value })}>
                        <option value="">{mainOption()}</option><TargetOptions current={after.primary} />
                      </select>
                    </label>
                    <FallbackPicker primary={after.primary} value={after.fallback} onchange={(v) => changeRow(row, { fallback: v })} />
                  {/if}
                </details>
              {/if}
            {:else}<small class="chain">{row.action === 'direct' ? 'Напрямую' : 'Заблокировать'}</small>{/if}
          </div>
        {/each}
      {/each}
    {/if}
  </fieldset>
  <div class="footer">
    {#if error}
      <p class="note error" role="alert">{hide(error)}</p>
      <button disabled={loading || saving} onclick={() => loadScope(scope, true)}>Загрузить правила заново</button>
    {/if}
    <div class="actions">
      <span class="small muted">Изменится строк: {edits.length}</span>
      <button onclick={onclose} disabled={saving}>Отмена</button>
      <button class="primary" disabled={loading || loadError || saving || !edits.length} onclick={save}>{saving ? 'Сохранение…' : 'Сохранить'}</button>
    </div>
  </div>
</AssignmentDialog>

<style>
  fieldset { padding: 0; margin: 0; border: 0; min-width: 0; }
  .fields { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 10px; margin: 12px 0; }
  .fields label, .field { display: grid; gap: 4px; font-size: 13px; }
  select { min-width: 0; width: 100%; }
  .common { display: grid; gap: 9px; padding: 12px; background: var(--surface-2); border-radius: 8px; }
  .pick { display: flex; align-items: center; gap: 8px; cursor: pointer; }
  .select-all { margin: 16px 0; }
  .legend { display: block; margin-top: 12px; }
  .line { padding: 8px 0; border-top: 1px solid var(--border); }
  .unavailable { opacity: 0.65; }
  .chain { display: grid; gap: 2px; margin: 4px 0 0 26px; font-size: 13px; overflow-wrap: anywhere; }
  small { color: var(--muted); }
  details { margin: 4px 0 0 26px; }
  summary { cursor: pointer; font-size: 13px; color: var(--accent); }
  details .field { margin: 8px 0; }
  h3 { margin: 8px 0; }
  .common h3 { margin: 0; }
  .footer { position: sticky; bottom: -22px; padding: 8px 0; background: var(--surface); border-top: 1px solid var(--border); }
  .footer .actions { align-items: center; margin: 0; }
  .actions span { margin-right: auto; }
</style>
