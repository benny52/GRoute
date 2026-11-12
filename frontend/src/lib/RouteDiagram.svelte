<script lang="ts">
  import { type Explanation, type Flow } from '../api';
  import { ui, hide, hideUserPath, targetText } from '../state.svelte';
  import { observedExit } from './flowRoute';
  import Icon from './Icon.svelte';

  type Answer = Explanation & { q: { app: string; target: string; proto: string; ruleset: string } };
  type Node = { label: string; text: string; icon: string; detail?: string };
  let { answer, flow }: { answer: Answer | null; flow?: Flow } = $props();

  const planned = $derived.by((): Node[] => {
    if (!answer) return [];
    const { winner, q } = answer;
    const vpn = winner.action === 'tunnel';
    return [
      { label: 'Программа', text: hideUserPath(q.app) || 'Не указана', icon: 'app' },
      { label: 'Назначение', text: q.target ? (ui.privacy ? 'Адрес скрыт' : q.target) : 'Любой адрес', icon: 'globe',
        detail: q.proto.toUpperCase() + (answer.port ? ' · порт ' + answer.port : '') },
      { label: 'Правило', text: winner.index === -1 ? 'Всё остальное' : hide(winner.name), detail: q.ruleset ? 'Профиль · ' + hide(q.ruleset) : undefined, icon: 'rules' },
      { label: vpn ? 'VPN · приоритетный' : 'Действие',
        text: vpn ? (winner.profile ? targetText(winner.profile) : 'Сервер не выбран') : winner.action === 'direct' ? 'DIRECT · напрямую' : 'BLOCK · блокировка',
        detail: vpn && answer.usesMain ? 'Основной сервер с главной' : undefined,
        icon: vpn ? 'server' : winner.action === 'direct' ? 'globe' : 'ban' },
    ];
  });
  const exit = $derived(flow ? observedExit(flow) : undefined);
  const observed = $derived.by((): Node[] => {
    if (!flow || !exit) return [];
    const dest = ui.privacy ? ['Адрес скрыт'] : [flow.domain, flow.dst].filter(Boolean);
    return [
      { label: 'Программа', text: hideUserPath(flow.process || flow.path) || 'Не определена', icon: 'app' },
      { label: 'Назначение', text: dest[0] || 'Неизвестно', detail: dest.slice(1).join(' · '), icon: 'globe' },
      { label: flow.excluded ? 'Исключение' : 'Правило при соединении', text: hide(flow.rule) || 'Не записано', icon: 'rules' },
      { label: exit.kind === 'vpn' ? 'VPN · фактический выход' : 'Исход',
        text: exit.serverId ? targetText(exit.serverId) : exit.label ?? (exit.kind === 'block' ? 'BLOCK · заблокировано' : exit.kind === 'direct' ? 'DIRECT · напрямую' : 'Выход неизвестен'),
        icon: exit.kind === 'vpn' ? 'server' : exit.kind === 'block' ? 'ban' : 'globe',
        detail: [exit.kind === 'vpn' && flow.group && targetText(flow.group), flow.failover && exit.serverId && 'Использован запасной'].filter(Boolean).join(' · ') },
    ];
  });
</script>

{#snippet path(nodes: Node[], title: string, tone: string)}
  <section class="path {tone}" aria-label={title}>
    <h3><span class="marker"></span>{title}</h3>
    <ol class="nodes">
      {#each nodes as node}
        <li>
          <span class="label"><Icon name={node.icon} size={14} />{node.label}</span>
          <strong>{node.text}</strong>
          {#if node.detail}<small>{node.detail}</small>{/if}
        </li>
      {/each}
    </ol>
  </section>
{/snippet}

{#if flow && exit}
  {@render path(observed, 'По записи соединения', exit.kind === 'vpn' ? 'tunnel' : exit.kind)}
{/if}
{#if answer}
  <div class="result">
    {@render path(planned, 'По правилам', answer.winner.action)}
    <p class="reason"><b>Почему</b> · {hideUserPath(answer.winner.reason || '')}</p>
    {#if answer.winner.action === 'tunnel'}
      {#if answer.fallback?.length}
        <div class="reserves"><span>Запасные по порядку</span>
          <ol>{#each answer.fallback as id}<li>{targetText(id)}</li>{/each}</ol>
        </div>
      {:else if !answer.winner.profile}
        <p class="reason">Нет доступного назначения. Соединение будет отклонено.</p>
      {/if}
      {#if answer.group && answer.via}<p class="reason">Выбор группы на момент расчёта · {hide(answer.via)}</p>{/if}
    {/if}
  </div>
{/if}

<style>
  .path { --line: var(--muted); margin-top: 16px; }
  .direct { --line: var(--direct); } .block { --line: var(--block); } .tunnel { --line: var(--tunnel); }
  h3 { display: flex; gap: 7px; align-items: center; margin: 0 0 8px; font-size: 13px; }
  .marker { background: var(--line); border-radius: 50%; width: 8px; height: 8px; }
  .nodes { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin: 0; padding: 0; list-style: none; }
  .nodes li { position: relative; display: flex; flex-direction: column; gap: 5px; justify-content: center; padding: 10px; min-width: 0; border: 1px solid var(--border); border-radius: 8px; background: var(--surface-2); overflow-wrap: anywhere; }
  .nodes li + li::before { content: ''; position: absolute; width: 15px; height: 2px; right: calc(100% + 1px); top: 50%; background: var(--line); }
  .nodes li + li::after { content: ''; position: absolute; right: calc(100% + 1px); top: calc(50% - 3px); border-block: 4px solid transparent; border-left: 5px solid var(--line); }
  .nodes li:last-child { border-color: var(--line); }
  .label, small, .reserves > span { font-size: 12px; color: var(--muted); }
  .label { display: flex; align-items: center; gap: 5px; }
  strong { font-size: 13px; }
  .reason { font-size: 13px; margin: 8px 0; }
  .reserves { display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px; }
  .reserves ol { margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 6px 14px; list-style-position: inside; font-size: 13px; }
  @container (max-width: 540px) {
    .nodes { grid-template-columns: 1fr; gap: 12px; }
    .nodes li + li::before { width: 2px; height: 11px; left: 19px; top: -12px; }
    .nodes li + li::after { left: 16px; right: auto; top: -5px; border: 4px solid transparent; border-top-color: var(--line); }
  }
</style>
