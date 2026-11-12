<script lang="ts">
  // Fallback servers (or groups) of a "через VPN" route: tried in order
  // when the route's own server is down. "" is the main server.
  import { isGroupId } from '../api';
  import { ui, hide, mainTarget, mainText, profileName } from '../state.svelte';
  import Icon from './Icon.svelte';

  let { value, primary, onchange, compact = false }: { value: string[]; primary?: string; onchange: (v: string[]) => void; compact?: boolean } =
    $props();

  const main = $derived(mainTarget());
  // Labels as in the other server selects (TargetOptions): servers of
  // the same name from different subscriptions differ by the
  // subscription's name.
  const label = (id: string) => {
    if (!id) return `Основной сервер — ${main ? mainText(main) : 'не выбран'}`;
    if (isGroupId(id)) return `«${profileName(id)}» (группа)`;
    const p = ui.profiles.find((x) => x.id === id);
    if (!p) return 'удалённый сервер';
    return `${hide(p.name)}${p.sourceName ? ` · ${hide(p.sourceName)}` : ''}${p.missing ? ' — нет в подписке' : ''}`;
  };
  // Compare saved assignments by ID, and effective routes by today's main.
  const key = (id: string) => id || main?.id || '';
  const taken = (id: string) => id === primary || value.includes(id);
  // A copy of another server (the very same connection: duplicateOf)
  // would only repeat it as a reserve: the kept one is offered instead.
  const servers = $derived(ui.profiles.filter((p) => !p.duplicateOf && !taken(p.id)));
  const groups = $derived(ui.groups.filter((g) => !taken(g.id)));
  const offerMain = $derived(!taken(''));
  function skipped(i: number): string {
    const id = value[i];
    if (id === primary || value.slice(0, i).includes(id)) return 'Повтор назначения. Уберётся при сохранении.';
    if (id === '' && !main) return 'Ожидает основной сервер';
    if ((primary !== undefined && key(id) === key(primary)) || value.slice(0, i).some((v) => key(v) === key(id))) {
      return 'Сейчас совпадает с предыдущим сервером. Назначение сохранится при смене основного.';
    }
    return '';
  }
  function move(index: number, by: number) {
    const next = [...value];
    [next[index], next[index + by]] = [next[index + by], next[index]];
    onchange(next);
  }
</script>

<div class="fb" class:compact>
  {#if !compact}<span class="muted">Запасные серверы</span>{/if}
  <div class="list">
    {#each value as id, i (i + ':' + id)}
      <span
        class="chip"
        class:idle={!!skipped(i)}
        title={skipped(i) || 'Используется, если недоступны серверы левее'}
      >
        <span class="n">{i + 1}</span>
        <span class="ellipsis">{label(id)}</span>
        {#if value.length > 1}
          <button class="x" disabled={i === 0} onclick={() => move(i, -1)} aria-label={`Поднять запасной сервер № ${i + 1}`}>↑</button>
          <button class="x" disabled={i === value.length - 1} onclick={() => move(i, 1)} aria-label={`Опустить запасной сервер № ${i + 1}`}>↓</button>
        {/if}
        <button class="x" onclick={() => onchange(value.filter((_, j) => j !== i))} title="Убрать"><Icon name="x" size={12} /></button>
      </span>
    {/each}
    {#if offerMain || servers.length || groups.length}
      <select
        aria-label="Добавить запасной сервер"
        value="__add"
        onchange={(e) => {
          const v = (e.currentTarget as HTMLSelectElement).value;
          (e.currentTarget as HTMLSelectElement).value = '__add';
          if (v !== '__add') onchange([...value, v]);
        }}
      >
        <option value="__add" disabled>{value.length ? '+ ещё запасной' : '+ запасной сервер'}</option>
        {#if offerMain}<option value="">{label('')}</option>{/if}
        {#each servers as p (p.id)}<option value={p.id}>{label(p.id)}</option>{/each}
        {#if groups.length}
          <optgroup label="Группы серверов">
            {#each groups as g (g.id)}<option value={g.id}>{label(g.id)}</option>{/each}
          </optgroup>
        {/if}
      </select>
    {/if}
  </div>
</div>

<style>
  .fb { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .list { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; flex: 1; min-width: 0; }
  .chip { display: inline-flex; align-items: center; gap: 6px; max-width: 260px; padding: 3px 4px 3px 4px; border-radius: 999px; background: var(--surface-2); border: 1px solid var(--border); font-size: 13px; }
  .chip.idle { opacity: 0.55; text-decoration: line-through; }
  .n { width: 18px; height: 18px; border-radius: 50%; display: grid; place-items: center; font-size: 11px; background: var(--accent-soft); color: var(--accent); flex: none; }
  .x { padding: 2px; background: none; }
  select { width: auto; max-width: 240px; }
  .compact select { font-size: 12.5px; }
</style>
