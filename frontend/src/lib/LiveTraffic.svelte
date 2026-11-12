<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errText } from '../api';
  import { every } from '../poll';
  import { hide, profileName, ui } from '../state.svelte';
  import Icon from './Icon.svelte';
  import { sampleDirections, type Direction, type DirectionSample } from './liveDirections';

  import TrafficMap from './TrafficMap.svelte';

  let { mapView }: { mapView: boolean } = $props();
  let rows = $state.raw<Direction[]>([]);
  let ready = $state(false);
  let error = $state('');
  let limit = $state(20);

  onMount(() => {
    let previous: DirectionSample | null = null;
    let mounted = true;
    let busy = false;
    async function update() {
      if (busy) return;
      busy = true;
      try {
        const snapshot = await api.Connections(2000);
        if (!mounted) return;
        const result = sampleDirections(snapshot, previous, performance.now(), Date.now());
        previous = result.next;
        rows = result.rows;
        error = '';
        ready = true;
      } catch (e) {
        if (!mounted) return;
        error = errText(e);
        previous = null;
        rows = [];
      } finally {
        busy = false;
      }
    }
    update();
    const stop = every(update, 1000);
    return () => { mounted = false; stop(); };
  });

  const number = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 });
  function rate(bytes: number): string {
    if (bytes > 0 && bytes < 102.4) return '< 0,1 КБ/с';
    return number.format(bytes / 1024) + ' КБ/с';
  }
  function travelTime(bytes: number): string {
    return Math.max(0.15, 2.5 / (1 + Math.log2(1 + bytes / 1024))) + 's';
  }
  function exitLabel(row: Direction): string {
    if (row.exit.serverId) return profileName(row.exit.serverId);
    if (row.exit.label) return row.exit.label;
    return row.exit.kind === 'direct' ? 'Напрямую' : 'Заблокировано';
  }
</script>

{#snippet track(row: Direction)}
  <div class="track" aria-hidden="true">
    {#if row.measured && (row.exit.kind === 'vpn' || row.exit.kind === 'direct')}
      {#if row.up > 0}<i style:animation-duration={travelTime(row.up)}></i>{/if}
      {#if row.down > 0}<i class="back" style:animation-duration={travelTime(row.down)}></i>{/if}
    {/if}
  </div>
{/snippet}

<section class="card traffic">
  <h2><Icon name="activity" size={18} /> {mapView ? 'Карта маршрутов' : 'Направления трафика'}</h2>
  {#if !mapView}<p class="muted small">Чем выше скорость, тем быстрее движутся точки. ↑ Отправлено, ↓ получено, «—» означает, что измерения нет. Адреса видны только во время просмотра.</p>{/if}
  {#if error}
    <p class="note error">{hide(error)}</p>
  {:else if !ready}
    <p class="muted">Ожидание данных…</p>
  {:else if mapView}
    <TrafficMap {rows} />
  {:else if !rows.length}
    <p class="empty muted">{ui.status?.state === 'disconnected' ? 'GRoute отключён.' : 'Сейчас нет наблюдаемых соединений.'}</p>
  {:else}
    <div class="columns small muted" aria-hidden="true"><span>Процесс</span><span>Правило · адрес</span><span>Выход</span><span>Скорость</span></div>
    <ul>
      {#each rows.slice(0, limit) as row (row.key)}
        <li class="flow-{row.exit.kind}">
          <span class="node"><Icon name="app" size={16} /><span><b>{hide(row.process) || 'Неизвестный процесс'}</b>{#if row.pid}<small>PID {row.pid}</small>{/if}</span></span>
          {@render track(row)}
          <span class="address"><b>{hide(row.rule)}</b><br />{ui.privacy ? 'Адрес скрыт' : row.destination || 'Адрес неизвестен'}</span>
          {@render track(row)}
          <span class="exit"><Icon name={row.exit.kind === 'vpn' ? 'server' : row.exit.kind === 'block' ? 'ban' : row.exit.kind === 'direct' ? 'globe' : 'info'} size={15} />{exitLabel(row)}</span>
          <span class="rates"><span title={row.exit.kind === 'direct' && !row.hasDown ? 'Отправлено примерно, включая повторные пакеты' : 'Отправлено'}>↑ {row.measured ? rate(row.up) : '—'}</span><span title={row.hasDown ? 'Получено' : 'Входящий трафик этого пути не измеряется'}>↓ {row.hasDown && row.measured ? rate(row.down) : '—'}</span></span>
        </li>
      {/each}
    </ul>
    {#if rows.length > limit}
      <button onclick={() => (limit += 20)}>Показать ещё ({rows.length - limit})</button>
    {/if}
  {/if}
</section>

<style>
  .traffic { --grid: minmax(80px, 1.2fr) minmax(15px, .35fr) minmax(75px, 1.2fr) minmax(15px, .35fr) minmax(114px, 1.15fr) minmax(80px, .7fr); }
  h2, .node, .exit { display:flex; align-items:center; gap:8px; }
  h2 { margin:0; }
  p { margin:6px 0 15px; }
  .columns, li { display:grid; grid-template-columns:var(--grid); gap:7px; align-items:center; }
  .columns { padding:8px 0; }
  .columns span:nth-child(2) { grid-column:3; }
  .columns span:nth-child(3) { grid-column:5; }
  .columns span:last-child { text-align:right; }
  ul { margin:0; padding:0; list-style:none; }
  li { border-top:1px solid var(--border); padding:12px 0; --ink:var(--muted); }
  .flow-direct { --ink:var(--direct); } .flow-vpn { --ink:var(--tunnel); } .flow-block { --ink:var(--block); }
  .node, .address, .exit { min-width:0; overflow-wrap:anywhere; font-size:13px; }
  .node :global(svg), .exit :global(svg) { flex:none; }
  .node small { display:block; margin-top:1px; color:var(--muted); }
  .exit :global(svg) { color:var(--ink); }
  .track { position:relative; height:9px; color:var(--ink); overflow:hidden; }
  .track:before { content:''; position:absolute; inset:4px 0 auto; border-top:1px solid currentColor; opacity:.5; }
  i { position:absolute; left:0; right:0; top:0; height:5px; background:radial-gradient(circle at 3px 50%, currentColor 1.7px, transparent 2.4px) repeat-x; background-size:22px 5px; animation:travel 1s linear infinite; }
  i.back { top:auto; bottom:0; animation-direction:reverse; }
  @keyframes travel { to {background-position-x:22px;} }
  .rates { text-align:right; font-variant-numeric:tabular-nums; font-size:12px; display:grid; gap:2px; white-space:nowrap; }
  .empty { padding:16px 0; }
  @media (prefers-reduced-motion:reduce) { i { animation:none; } }
  @media (max-width:850px) { .traffic { --grid:minmax(64px,1fr) minmax(8px,.22fr) minmax(60px,1fr) minmax(8px,.22fr) minmax(68px,1fr) auto; } .columns,li { gap:4px; } .node,.exit { gap:4px; } }
</style>
