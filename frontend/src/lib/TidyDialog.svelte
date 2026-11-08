<script lang="ts">
  // «Навести порядок»: what can go from a grown rule list. The user ticks
  // the suggestions; the page saves the result as any edit.
  import { onMount } from 'svelte';
  import { api, errText, type Settings, type Rule, type Tidy, type TidyView } from '../api';
  import { hide } from '../state.svelte';
  import Icon from './Icon.svelte';

  let { settings, onclose, onapply }: { settings: Settings; onclose: () => void; onapply: (rules: Rule[], n: number) => Promise<void> } = $props();

  let view = $state<TidyView | null>(null);
  let picked = $state<Record<string, boolean>>({});
  let error = $state('');
  let busy = $state(false);

  // Safe ones start ticked: they change nothing about where traffic goes.
  // Merges and lists change how the list reads or what it catches: the
  // user decides.
  const safe = (t: Tidy) => (t.kind === 'drop' || t.kind === 'sites') && !t.changes;

  onMount(async () => {
    try {
      // svelte-ignore state_referenced_locally
      const v = await api.TidyRules(settings, []);
      picked = Object.fromEntries(v.items.map((t) => [t.id, safe(t)]));
      view = v;
    } catch (e) {
      error = errText(e);
    }
  });

  const groups: { kind: Tidy['kind']; title: string; hint: string }[] = [
    { kind: 'drop', title: 'Лишние правила', hint: 'Они ничего не решают: всё, что они ловят, раньше забирают правила выше. Удаление ничего не меняет.' },
    { kind: 'sites', title: 'Лишние сайты в правилах', hint: 'Повторы и сайты, которые всё равно уходят по правилу выше. Удаление ничего не меняет.' },
    { kind: 'merge', title: 'Объединить правила', hint: 'Правила с одним маршрутом становятся одним — список короче. Сервисы будут в одном правиле: выключить один из них отдельно будет нельзя.' },
    { kind: 'geo', title: 'Списки из базы правил (dat)', hint: 'Вместо россыпи доменов — готовый список сервиса. Он обновляется с базой и ловит и те адреса сервиса, которых нет в правиле.' },
  ];

  const count = $derived(view ? view.items.filter((t) => picked[t.id]).length : 0);

  async function apply() {
    if (!view || busy || !count) return;
    busy = true;
    error = '';
    try {
      const accept = view.items.filter((t) => picked[t.id]).map((t) => t.id);
      const v = await api.TidyRules(settings, accept);
      await onapply(v.rules, accept.length);
    } catch (e) {
      error = errText(e);
    } finally {
      busy = false;
    }
  }

  function setAll(kind: Tidy['kind'], on: boolean) {
    for (const t of view?.items ?? []) if (t.kind === kind) picked[t.id] = on;
  }

  let downOnBackdrop = false;
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && !busy && onclose()} />

<div
  class="backdrop"
  role="presentation"
  onmousedown={(e) => (downOnBackdrop = e.target === e.currentTarget)}
  onclick={(e) => downOnBackdrop && e.target === e.currentTarget && !busy && onclose()}
>
  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="tidy-title">
    <div class="row"><h2 class="grow" id="tidy-title">Навести порядок</h2><button class="icon" onclick={onclose} title="Закрыть"><Icon name="x" /></button></div>

    {#if !view && !error}
      <p class="muted">Проверяю правила…</p>
    {:else if view}
      {#if !view.items.length}
        <div class="note ok">Всё в порядке: лишних правил, повторов и того, что можно заменить списком из базы, не нашлось.</div>
      {:else}
        <p class="muted small">Отметьте, что сделать: изменения сохранятся сразу, как обычная правка правил.</p>
      {/if}
      <div class="list">
        {#each groups as g (g.kind)}
          {@const items = view.items.filter((t) => t.kind === g.kind)}
          {#if items.length}
            <section>
              <div class="row head">
                <h3 class="grow">{g.title} <span class="muted">· {items.length}</span></h3>
                {#if items.length > 1}
                  <button class="link small" onclick={() => setAll(g.kind, !items.every((t) => picked[t.id]))}
                    >{items.every((t) => picked[t.id]) ? 'Снять все' : 'Отметить все'}</button
                  >
                {/if}
              </div>
              <p class="muted small">{g.hint}</p>
              {#each items as t (t.id)}
                <label class="item">
                  <input type="checkbox" bind:checked={picked[t.id]} />
                  <span class="body">
                    <span class="title">{hide(t.title)}</span>
                    {#if t.kind === 'merge' && t.name}<span class="muted small">Новое название: «{hide(t.name)}»</span>{/if}
                    {#each t.details ?? [] as d, i (i)}<span class="muted small">{hide(d)}</span>{/each}
                    {#if t.changes}<span class="warn small"><Icon name="alert" size={13} />Меняет, куда пойдёт часть соединений</span>{/if}
                  </span>
                </label>
              {/each}
            </section>
          {/if}
        {/each}
      </div>
      {#if view.geoNote}<div class="note info small">{hide(view.geoNote)}</div>{/if}
    {/if}

    {#if error}<div class="note error">{hide(error)}</div>{/if}

    <div class="actions">
      <button onclick={onclose} disabled={busy}>Закрыть</button>
      {#if view?.items.length}
        <button class="primary" onclick={apply} disabled={busy || !count}>{count ? `Применить (${count})` : 'Применить'}</button>
      {/if}
    </div>
  </div>
</div>

<style>
  .dialog { width: min(640px, 94vw); max-height: 88vh; display: flex; flex-direction: column; gap: 12px; }
  .list { overflow-y: auto; display: grid; gap: 16px; min-height: 0; padding-right: 4px; }
  section { display: grid; gap: 6px; }
  h3 { font-size: 14px; margin: 0; }
  .head { align-items: baseline; }
  section > p { margin: 0 0 2px; }
  .item { display: flex; gap: 10px; align-items: flex-start; padding: 8px 10px; border: 1px solid var(--border); border-radius: var(--radius-sm); cursor: pointer; }
  .item input { margin-top: 3px; flex: none; }
  .body { display: grid; gap: 3px; min-width: 0; overflow-wrap: anywhere; }
  .title { font-weight: 500; }
  .warn { color: var(--warn, #b7791f); display: inline-flex; align-items: center; gap: 4px; }
  .actions { margin-top: 0; }
</style>
