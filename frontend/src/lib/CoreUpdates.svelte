<script lang="ts">
  import { tick } from 'svelte';
  import { api, errText, fmtDateTime, type CoreUpdateState, type Updates } from '../api';
  import { ui, hide } from '../state.svelte';
  import Icon from './Icon.svelte';

  let { updates, onupdates, installHysteria, hysteriaInstalling, needsAdmin, online }: {
    updates: Updates;
    onupdates: () => Promise<void>;
    installHysteria: () => Promise<void>;
    hysteriaInstalling: boolean;
    needsAdmin: boolean | undefined;
    online: boolean;
  } = $props();

  type CoreRow = {
    name: string;
    source: string;
    state: CoreUpdateState;
    install: () => Promise<void>;
    rollback: () => Promise<void>;
  };

  const rows = $derived.by(() => {
    const list: CoreRow[] = [{
      name: 'Hysteria', source: 'Официальные выпуски Hysteria', install: installHysteria, rollback: () => api.RollbackCore(),
      state: { info: updates.core, update: updates.coreUpdate, busy: updates.coreBusy || hysteriaInstalling,
        error: updates.coreError, progress: updates.coreProgress, needsReconnect: updates.coreNeedsReconnect }
    }];
    if (updates.xray?.info) list.push({ name: 'Xray', source: 'Официальные выпуски Xray', state: updates.xray,
      install: () => api.InstallXray(), rollback: () => api.RollbackXray() });
    if (updates.awg?.info.version) list.push({ name: 'AmneziaWG', source: 'Сборки проекта GRoute', state: updates.awg,
      install: () => api.InstallAWG(), rollback: () => api.RollbackAWG() });
    return list;
  });
  const checked = $derived(!!updates.checked && !updates.checked.startsWith('0001'));
  let checking = $state(false);
  let changing = $state('');
  let error = $state('');
  let notice = $state('');
  let section: HTMLDivElement;

  async function check() {
    if (checking || updates.checking) return;
    checking = true;
    error = '';
    notice = '';
    try {
      await api.CheckUpdates();
      await onupdates();
    } catch (e) {
      error = errText(e);
    } finally {
      checking = false;
    }
  }

  // localStorage survives the portable UAC restart and is shared with the window
  // running afterwards. The marker authorizes only a fresh version check.
  const resumeKey = 'groute.showCoreUpdates';
  $effect(() => {
    if (needsAdmin !== false || !ui.portable || !localStorage.getItem(resumeKey)) return;
    localStorage.removeItem(resumeKey);
    tick().then(() => {
      section?.scrollIntoView({ block: 'center' });
      void check();
    });
  });

  async function change(row: CoreRow, rollback: boolean) {
    if (changing || (ui.portable && needsAdmin === undefined)) return;
    error = '';
    notice = '';
    changing = row.name;
    try {
      if (needsAdmin) {
        localStorage.setItem(resumeKey, '1');
        try {
          await api.RestartAsAdmin();
        } catch (e) {
          localStorage.removeItem(resumeKey);
          throw e;
        }
        return;
      }
      if (rollback) {
        if (!confirm(`Вернуть ядро ${row.name} к версии ${row.state.info.previous}?`)) return;
        await row.rollback();
        notice = `Возвращена предыдущая версия ${row.name}.`;
      } else {
        await row.install();
        notice = `Ядро ${row.name} обновлено.`;
      }
    } catch (e) {
      error = errText(e);
    } finally {
      await onupdates();
      changing = '';
    }
  }

  const working = $derived(!!changing || checking || updates.checking || rows.some(row => row.state.busy));
</script>

<div class="cores" bind:this={section}>
  <div class="toolbar">
    <button class="primary" disabled={working} onclick={check}>
      <Icon name="download" size={15} />{checking || updates.checking ? 'Проверка…' : 'Проверить обновления'}
    </button>
    {#if checked}<span class="muted">Проверено {fmtDateTime(updates.checked)}</span>{/if}
  </div>
  {#each rows as row (row.name)}
    {@const s = row.state}
    {@const awg = row.name === 'AmneziaWG' ? updates.awg : undefined}
    <div class="core-row" role="group" aria-label={row.name}>
      <div class="identity"><strong>{row.name}</strong><small class="muted">{row.source}</small></div>
      <div class="version">
        <span>{awg ? 'Программа groute-awg.exe' : 'Установлено'} <b>{s.info.version}</b></span>
        {#if s.info.error}<span class="problem">{hide(s.info.error)}</span>{/if}
        {#if s.busy}<span role="status">Загрузка и проверка · {Math.round(s.progress * 100)}%</span>
        {:else if s.error}<span class="problem">{hide(s.error)}</span>
        {:else if s.update}<span>Доступно <b>{s.update.version}</b></span>
        {:else if s.unpublished}<span class="muted">Отдельных выпусков пока нет</span>
        {:else if checked}<span class="muted">{awg ? 'Новых сборок GRoute нет' : 'Обновлений нет'}</span>{/if}
        {#if awg}
          <div class="library">
            <span>Библиотека AmneziaWG <b>{awg.engineVersion || '—'}</b></span>
            {#if awg.upstreamError}
              <span class="problem">Не удалось проверить версию у Amnezia. {hide(awg.upstreamError)}</span>
            {:else if awg.upstreamVersion && awg.upstreamNewer}
              <span>У Amnezia вышла <b>{awg.upstreamVersion}</b>. {#if !s.update && !s.error}Ожидается совместимая сборка GRoute.{/if}</span>
            {:else if awg.upstreamVersion && awg.engineVersion}
              <span class="muted">Библиотека актуальна. Версия у Amnezia — {awg.upstreamVersion}.</span>
            {:else if awg.upstreamVersion}
              <span class="muted">Версия у Amnezia — {awg.upstreamVersion}. Установленную версию определить не удалось.</span>
            {/if}
          </div>
        {/if}
        {#if s.needsReconnect && online}<span>Новая версия заработает после переподключения.</span>{/if}
      </div>
      <div class="actions">
        {#if s.update && !s.error}
          <button class="primary" disabled={working || (ui.portable && needsAdmin === undefined)} onclick={() => change(row, false)} aria-label={'Обновить ' + row.name}>
            {#if needsAdmin}<Icon name="shield" size={14} />{/if}Обновить
          </button>
        {/if}
        {#if s.info.previous}
          <button disabled={working || (ui.portable && needsAdmin === undefined)} onclick={() => change(row, true)} aria-label={'Откатить ' + row.name}>
            Откатить до {s.info.previous}
          </button>
        {/if}
      </div>
    </div>
  {/each}
  {#if needsAdmin && rows.some(row => row.state.update || row.state.info.previous)}
    <p class="muted">Для установки или отката Windows запросит права администратора. После перезапуска GRoute снова проверит версии. Выберите нужное ядро, чтобы продолжить.</p>
  {/if}
  {#if error}<div class="note error" role="alert">{hide(error)}</div>{/if}
  {#if notice}<div class="note ok" role="status">{notice}</div>{/if}
</div>

<style>
  .cores { margin-block: 12px; }
  .toolbar,.actions { display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
  .toolbar { margin-bottom:10px; font-size:12px; }
  .core-row { display:grid; grid-template-columns:minmax(8rem,.7fr) minmax(10rem,1.3fr) auto; align-items:center; gap:16px; padding:12px 0; border-top:1px solid var(--border); }
  .version,.identity { display:grid; gap:3px; min-width:0; overflow-wrap:anywhere; }
  .version { font-size:13px; }
  .library { display:grid; gap:3px; margin-top:5px; }
  .problem { color:var(--block); }
  .actions { justify-content:flex-end; }
  p { margin:8px 0 0; font-size:12px; }
  @media (max-width: 850px) {
    .core-row { grid-template-columns:minmax(0,1fr) minmax(0,1.4fr); gap:8px; }
    .actions:not(:empty) { grid-column:2; justify-content:flex-start; }
    .actions:empty { display:none; }
  }
</style>
