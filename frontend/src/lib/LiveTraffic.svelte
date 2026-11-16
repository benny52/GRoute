<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errText } from '../api';
  import { every } from '../poll';
  import { hide, profileName, ui } from '../state.svelte';
  import Icon from './Icon.svelte';
  import { sampleDirections, type Direction, type DirectionSample } from './liveDirections';

  import TrafficMap from './TrafficMap.svelte';
  import FlowRuleActions, { type FlowMenu } from './FlowRuleActions.svelte';

  let { mapView }: { mapView: boolean } = $props();
  let rows = $state.raw<Direction[]>([]);
  let ready = $state(false);
  let error = $state('');
  let limit = $state(20);
  let menu = $state.raw<FlowMenu | null>(null);

  function openMenu(event: MouseEvent | KeyboardEvent, directions: Direction[], appOnly: boolean) {
    if (!directions.length) return;
    event.preventDefault();
    const el = event.currentTarget as HTMLElement;
    const rect = el.getBoundingClientRect();
    const anchor = event instanceof MouseEvent && (event.clientX || event.clientY)
      ? { x: event.clientX, y: event.clientY } : { x: rect.left, y: rect.bottom };
    const choices = directions.map(row => row.flow);
    menu = { flow: choices[0], choices, anchor, el, appOnly };
  }

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
  <div class="track" class:duplex={row.up > 0 && row.down > 0} aria-hidden="true">
    {#if row.measured && (row.exit.kind === 'vpn' || row.exit.kind === 'direct')}
      {#if row.up > 0}<i style:animation-duration={travelTime(row.up)}></i>{/if}
      {#if row.down > 0}<i class="back" style:animation-duration={travelTime(row.down)}></i>{/if}
    {/if}
  </div>
{/snippet}

<section class="card traffic">
  <h2><Icon name="activity" size={18} /> {mapView ? 'Карта маршрутов' : 'Направления трафика'}</h2>
  {#if !mapView}<p class="muted small">Стрелки вправо показывают отправку, влево — получение. Чем выше скорость, тем быстрее они движутся. Прочерк означает, что измерения нет.</p>{/if}
  {#if error}
    <p class="note error">{hide(error)}</p>
  {:else if !ready}
    <p class="muted">Ожидание данных…</p>
  {:else if mapView}
    <TrafficMap {rows} onmenu={openMenu} />
  {:else if !rows.length}
    <p class="empty muted">{ui.status?.state === 'disconnected' ? 'GRoute отключён.' : 'Сейчас нет наблюдаемых соединений.'}</p>
  {:else}
    <div class="columns small muted" aria-hidden="true"><span>Процесс</span><span>Правило · адрес</span><span>Выход</span><span>Скорость</span></div>
    <ul>
      {#each rows.slice(0, limit) as row (row.key)}
        <li class="flow-{row.exit.kind}" oncontextmenu={(e) => openMenu(e, [row], false)}>
          <button class="node ghost" title="Действия с соединением" aria-haspopup="menu" onclick={(e) => openMenu(e, [row], false)}><Icon name="app" size={16} /><span><b>{hide(row.process) || 'Неизвестный процесс'}</b>{#if row.pid}<small>PID {row.pid}</small>{/if}</span></button>
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
<FlowRuleActions bind:menu />

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
  .node { justify-content:flex-start; text-align:start; padding:4px; }
  .exit :global(svg) { color:var(--ink); }
  .track { position:relative; height:18px; color:var(--ink); overflow:hidden; }
  .track:before { content:''; position:absolute; inset:50% 0 auto; border-top:1px solid currentColor; opacity:.35; }
  .track i { position:absolute; inset:5px 0 auto; height:8px; animation:travel 1s linear infinite; }
  .track i::before { content:''; display:block; width:12px; height:100%; background:currentColor; clip-path:polygon(0 37%, 58% 37%, 58% 0, 100% 50%, 58% 100%, 58% 63%, 0 63%); }
  .track .back { animation-direction:reverse; }
  .back::before { transform:scaleX(-1); }
  .duplex i { top:0; }
  .duplex .back { top:10px; }
  @keyframes travel { from { transform:translateX(-12px); } to { transform:translateX(100%); } }
  .rates { text-align:right; font-variant-numeric:tabular-nums; font-size:12px; display:grid; gap:2px; white-space:nowrap; }
  .empty { padding:16px 0; }
  @media (prefers-reduced-motion:reduce) { .track i { animation:none; transform:translateX(calc(50% - 6px)); } }
  @media (max-width:850px) { .traffic { --grid:minmax(64px,1fr) minmax(8px,.22fr) minmax(60px,1fr) minmax(8px,.22fr) minmax(68px,1fr) auto; } .columns,li { gap:4px; } .node,.exit { gap:4px; } }
</style>
