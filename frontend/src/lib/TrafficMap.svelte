<script lang="ts">
  import type { Direction } from './liveDirections';
  import { api, errText, type Rule, type Settings } from '../api';
  import { hide, hideUserPath, mainTarget, profileName, targetText, ui } from '../state.svelte';
  import Icon from './Icon.svelte';
  import Help from './Help.svelte';

  let { rows }: { rows: Direction[] } = $props();
  type Point = { key: string; label: string; icon: string };
  type Route = { key: string; nodes: Point[]; up: number; down: number; observed: boolean };
  type Wire = { from: number; to: number; layer: number; up: number; down: number };
  const headings = ['Приложения', 'Правила', 'Выходы'];
  const pageSize = 24;
  let showAll = $state(false);
  let limit = $state(pageSize);
  let selected = $state('');
  let paused = $state(false);
  let width = $state(700);
  let settings = $state.raw<Settings | null>(null);
  let settingsError = $state('');
  $effect(() => {
    if (!showAll) return;
    void ui.settingsRev;
    let stale = false;
    api.Settings().then(value => {
      if (!stale) { settings = value; settingsError = ''; }
    }).catch(e => {
      if (!stale) { settings = null; settingsError = errText(e); }
    });
    return () => { stale = true; };
  });

  const routes = $derived.by(() => {
    const grouped = new Map<string, Route>();
    // A name-only rule can share an observed app node when its executable is unambiguous.
    const sourceByName = new Map<string, string | null>();
    for (const row of rows) {
      const name = row.process.toLowerCase();
      const source = row.source.toLowerCase();
      sourceByName.set(name, !sourceByName.has(name) || sourceByName.get(name) === source ? source : null);
    }
    for (const row of rows) {
      const exit = row.exit;
      const nodes = [
        { key: 'app:' + row.source.toLowerCase(), label: hide(row.process) || 'Неизвестный процесс', icon: 'app' },
        { key: 'rule:' + row.rule, label: row.rule === 'default' ? 'Всё остальное' : hide(row.rule), icon: 'rules' },
        { key: JSON.stringify([exit.kind, exit.serverId, exit.label]), label: exit.serverId ? profileName(exit.serverId) :
          exit.label || (exit.kind === 'direct' ? 'Напрямую' : 'Заблокировано'),
          icon: exit.kind === 'vpn' ? 'server' : exit.kind === 'direct' ? 'globe' : exit.kind === 'block' ? 'ban' : 'info' },
      ];
      const key = JSON.stringify(nodes.map(n => n.key));
      const route = grouped.get(key) ?? { key, nodes, up: 0, down: 0, observed: true };
      if (row.measured && (exit.kind === 'vpn' || exit.kind === 'direct')) {
        route.up += row.up;
        route.down += row.down;
      }
      grouped.set(key, route);
    }
    if (showAll && settings) {
      const rest: Rule = { name: 'Всё остальное', action: settings.defaultAction,
        profile: settings.defaultProfile, fallback: settings.defaultFallback };
      for (const rule of [...settings.rules, rest]) {
        if (rule.enabled === false) continue;
        const apps = rule.apps?.length ? rule.apps : rule.app ? [rule.app] : [];
        const sources = apps.length ? apps.map(a => a.pattern).filter(Boolean) : [''];
        const targets = rule.action === 'tunnel' ? [rule.profile || '', ...(rule.fallback ?? [])] : [''];
        for (const source of sources) {
          for (const target of targets) {
            const server = target || mainTarget()?.id;
            const vpn = rule.action === 'tunnel';
            const kind = vpn ? 'vpn' : rule.action;
            const exitKey = JSON.stringify([kind, vpn ? server : undefined, undefined]);
            const nodes = [
              { key: source ? 'app:' + (sourceByName.get(source.toLowerCase()) || source.toLowerCase()) : 'any-app', label: source ? hideUserPath(source) : 'Любая программа', icon: 'app' },
              { key: 'rule:' + (rule === rest ? 'default' : rule.name), label: hide(rule.name) || 'Без названия', icon: 'rules' },
              { key: exitKey, label: vpn ? (server ? targetText(server) : 'Основной не выбран') : kind === 'direct' ? 'Напрямую' : 'Заблокировано',
                icon: vpn ? 'server' : kind === 'direct' ? 'globe' : 'ban' }
            ];
            const key = JSON.stringify(nodes.map(n => n.key));
            if (!grouped.has(key)) grouped.set(key, { key, nodes, up: 0, down: 0, observed: false });
          }
        }
      }
    }
    return [...grouped.values()].sort((a, b) => Number(b.observed) - Number(a.observed) || a.key.localeCompare(b.key));
  });
  const graph = $derived.by(() => {
    const matching = selected ? routes.filter(p => p.nodes.some(n => n.key === selected)) : [];
    const focus = matching.length ? selected : '';
    const available = focus ? matching : routes;
    const paths = available.slice(0, limit);
    // Keep neighbouring nodes together. A rate change must not rearrange the map.
    const columns = headings.map((_, i) => [...new Map(paths.map(p => [p.nodes[i].key, p.nodes[i]])).values()]);
    const positions = columns.map(col => new Map(col.map((n,i) => [n.key,i])));
    const edges = new Map<string, Wire>();
    for (const route of paths) {
      for (const layer of [0, 1]) {
        const a = route.nodes[layer].key, b = route.nodes[layer+1].key;
        const key = JSON.stringify([layer,a,b]);
        const wire = edges.get(key) ?? { layer, from: positions[layer].get(a)!, to: positions[layer+1].get(b)!, up: 0, down: 0 };
        wire.up += route.up;
        wire.down += route.down;
        edges.set(key, wire);
      }
    }
    // Draw moving packets on top at crossings.
    const wires = [...edges].map(([key,wire]) => ({ key,...wire })).sort((a,b) => Number(!!(a.up || a.down)) - Number(!!(b.up || b.down)));
    return { columns, focus, wires, remaining: available.length - paths.length };
  });
  const spacing = 54;
  const height = $derived(Math.max(...graph.columns.map(c => c.length)) * spacing);
  const columnOffsets = $derived(graph.columns.map((column, index) => index === 1 ? 0 : (height - column.length * spacing) / 2));
  function path(wire: Wire) {
    const x = width * (wire.layer * .38 + .24);
    const end = width * ((wire.layer + 1) * .38);
    const mid = (x + end) / 2;
    const y = columnOffsets[wire.layer] + (wire.from + 0.5) * spacing;
    const yy = columnOffsets[wire.layer + 1] + (wire.to + 0.5) * spacing;
    return 'M '+x+' '+y+' C '+mid+' '+y+' '+mid+' '+yy+' '+end+' '+yy;
  }
  function speed(bytes: number) { return Math.max(.5, 2.4 / (1 + Math.log2(1 + bytes/1024) / 3)) + 's'; }
  function switchView(all: boolean) {
    showAll = all;
    selected = '';
    limit = pageSize;
  }
</script>

<div class="tools">
  <div class="seg" role="group" aria-label="Маршруты на карте">
    <button class:on={!showAll} aria-pressed={!showAll} onclick={() => switchView(false)}>Текущие соединения</button>
    <button class:on={showAll} aria-pressed={showAll} onclick={() => switchView(true)}>Все маршруты</button>
  </div>
  {#if graph.focus}<button class="ghost" onclick={() => selected = ''}>Снять выделение</button>{/if}
  <button class="pause ghost" aria-pressed={paused} onclick={() => paused = !paused}>{paused ? 'Возобновить движение' : 'Приостановить движение'}</button>
</div>
<Help id="traffic-map" title="Как читать карту">
  <p>Слева направо идёт отправка, справа налево — получение. Чем выше скорость, тем быстрее движутся пакеты. Нажмите приложение, правило или выход, чтобы оставить только его пути. «Все маршруты» добавляет назначения из правил и запасные серверы.</p>
</Help>
{#if showAll && settingsError}<p class="note warn">Не удалось прочитать настройки маршрутов: {hide(settingsError)}</p>{/if}
{#if !routes.length}
  <p class="empty muted">{showAll ? (settings ? 'Маршрутов пока нет.' : settingsError ? 'Нет наблюдаемых соединений.' : 'Загрузка маршрутов…') : 'Сейчас нет наблюдаемых соединений.'}</p>
{:else}
  <div class="viewport">
    <div class="diagram">
      <div class="head">{#each headings as h}<strong>{h}</strong>{/each}</div>
      <div class="board" bind:clientWidth={width} style:height={height + 'px'} style:--row={spacing + 'px'}>
        <svg class="wires" aria-hidden="true" class:paused width="100%" height="100%">
          {#each graph.wires as w (w.key)}
            {@const d = path(w)}
            <g class="wire" class:active={w.up > 0 || w.down > 0}>
              <path {d} class="rim" /><path {d} class="bore" />
              {#if w.up > 0}<path {d} class="packet" style:animation-duration={speed(w.up)} transform={w.down ? 'translate(0 -2)' : undefined} />{/if}
              {#if w.down > 0}<path {d} class="packet reverse" style:animation-duration={speed(w.down)} transform={w.up ? 'translate(0 2)' : undefined} />{/if}
            </g>
          {/each}
        </svg>
        {#each graph.columns as column, index}
          <div class="column" style:padding-top={columnOffsets[index] + 'px'}>
            {#each column as n (n.key)}
              <button class="node" aria-pressed={graph.focus === n.key} title={n.label} onclick={() => selected = selected === n.key ? '' : n.key}>
                <Icon name={n.icon} size={16} /><span>{n.label}</span>
              </button>
            {/each}
          </div>
        {/each}
      </div>
    </div>
  </div>
  {#if graph.remaining}<button class="ghost" onclick={() => limit += pageSize}>Показать ещё маршруты ({graph.remaining})</button>{/if}
{/if}

<style>
  .tools { display:flex; align-items:center; flex-wrap:wrap; gap:8px; margin:10px 0; }
  .pause { margin-inline-start:auto; }
  .viewport { overflow-x:auto; margin-top:12px; }
  .diagram { min-width:460px; }
  .head,.board { display:grid; grid-template-columns:repeat(3,24%); justify-content:space-between; }
  .head { color:var(--muted); font-size:12px; padding:8px 0; border-bottom:1px solid var(--border); }
  .head strong { padding-inline:9px; }
  .board { position:relative; isolation:isolate; }
  .wires { position:absolute; inset:0; z-index:-1; pointer-events:none; }
  .wire path { fill:none; }
  .rim { stroke:color-mix(in srgb,var(--muted) 50%,var(--border)); stroke-width:12; }
  .bore { stroke:var(--surface); stroke-width:9; }
  .active .rim { stroke:color-mix(in srgb,var(--accent) 48%,var(--muted)); }
  .active .bore { stroke:color-mix(in srgb,var(--accent) 7%,var(--surface)); }
  .packet { stroke:var(--accent); stroke-width:2.8; stroke-linecap:round; stroke-dasharray:12 38; animation:run linear infinite; }
  .reverse { stroke:var(--direct); animation-direction:reverse; }
  .paused .packet { animation-play-state:paused; }
  @keyframes run { from { stroke-dashoffset:50; } to { stroke-dashoffset:0; } }
  @media (prefers-reduced-motion:reduce) { .packet { animation:none; } }
  .column { display:grid; align-content:start; grid-auto-rows:var(--row); align-items:center; min-width:0; }
  .node { display:flex; justify-content:flex-start; align-items:center; gap:7px; width:100%; height:38px; padding:0 9px; border:1px solid var(--border); border-radius:7px; background:var(--surface); text-align:left; }
  .node:hover,.node[aria-pressed=true] { border-color:var(--accent); background:color-mix(in srgb,var(--accent) 7%,var(--surface)); }
  .node span { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .node :global(svg) { flex:none; }
</style>
