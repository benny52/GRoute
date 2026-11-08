<script lang="ts">
  // «Пустить … через VPN»: first what the user's rules already do with the
  // service, then where to send it. The user's own rule for the service is
  // changed rather than a second one added.
  import { onMount } from 'svelte';
  import { api, errText, type ZapretRoute, type ZapretTarget } from '../api';
  import { hide, mainText } from '../state.svelte';
  import Icon from './Icon.svelte';
  import TargetOptions from './TargetOptions.svelte';

  let { target, onclose, ondone }: { target: ZapretTarget; onclose: () => void; ondone: (msg: string) => void } = $props();

  let route = $state<ZapretRoute | null>(null);
  let how = $state<'rules' | 'server'>('server');
  let server = $state('');
  let editOwn = $state(true);
  let error = $state('');
  let busy = $state(false);

  const own = $derived(route?.by.find((b) => b.own && b.id) ?? null);

  onMount(async () => {
    try {
      // svelte-ignore state_referenced_locally
      const r = await api.ZapretRoute(target);
      route = r;
      how = r.tunnel ? 'rules' : 'server';
      const o = r.by.find((b) => b.own && b.id);
      server = r.via && r.via !== 'rules' ? r.via : (o?.tunnel ? o.profile : '');
    } catch (e) {
      error = errText(e);
    }
  });

  const shown = (sites: string[]) => (sites.length <= 3 ? sites.join(', ') : `${sites.slice(0, 2).join(', ')} и ещё ${sites.length - 2}`);

  async function submit() {
    if (!route || busy) return;
    busy = true;
    error = '';
    try {
      const editRule = how === 'server' && own && editOwn ? own.id : '';
      await api.ZapretViaVPN({ target, via: how === 'rules' ? 'rules' : server, editRule });
      ondone(
        how === 'rules'
          ? `${route.name} идёт по вашим правилам, без обхода`
          : editRule
            ? `${route.name} идёт через VPN: правило «${own!.name}» изменено`
            : `${route.name} теперь идёт через VPN`,
      );
    } catch (e) {
      error = errText(e);
    } finally {
      busy = false;
    }
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
  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="zv-title">
    <div class="row"><h2 class="grow" id="zv-title">{route?.name ?? ''} через VPN</h2><button class="icon" onclick={onclose} title="Закрыть"><Icon name="x" /></button></div>
    {#if !route && !error}
      <p class="muted">Смотрю ваши правила…</p>
    {:else if route}
      <div class="now">
        <div class="lbl">Сейчас по вашим правилам (без обхода)</div>
        <ul>
          {#each route.by as b (b.id + b.name)}
            <li>
              <b>{b.id ? `«${hide(b.name)}»` : 'Всё остальное'}</b> → {hide(b.route)}
              <span class="muted small">— {hide(shown(b.sites))}</span>
            </li>
          {/each}
        </ul>
      </div>

      <fieldset>
        {#if route.tunnel}
          <label class="check"
            ><input type="radio" name="zv-how" value="rules" bind:group={how} />Как в ваших правилах
            <span class="muted small">— HyRoute не добавит своего правила</span></label
          >
        {/if}
        <label class="check"><input type="radio" name="zv-how" value="server" bind:group={how} />Через сервер</label>
        <select bind:value={server} disabled={how !== 'server'} aria-label="Сервер">
          <option value="">Основной: {hide(mainText())}</option>
          <TargetOptions current={server} />
        </select>
        {#if how === 'server'}
          {#if own}
            <label class="check small"
              ><input type="checkbox" bind:checked={editOwn} />Изменить ваше правило «{hide(own.name)}»: оно пойдёт через выбранный сервер</label
            >
            {#if !editOwn}<span class="muted small">Иначе HyRoute будет держать своё правило «Обход DPI: {route.name}» выше вашего.</span>{/if}
          {:else}
            <span class="muted small"
              >Отдельного правила для {route.name} у вас нет: HyRoute будет держать своё «Обход DPI: {route.name}» через этот сервер, пока сервис идёт через
              VPN.</span
            >
          {/if}
        {/if}
      </fieldset>
    {/if}
    {#if error}<div class="note error">{hide(error)}</div>{/if}
    <div class="actions">
      <button onclick={onclose} disabled={busy}>Отмена</button>
      <button class="primary" onclick={submit} disabled={busy || !route}>Пустить через VPN</button>
    </div>
  </div>
</div>

<style>
  .dialog { width: min(560px, 94vw); display: grid; gap: 12px; }
  .lbl { color: var(--muted); font-weight: 500; margin-bottom: 4px; }
  ul { margin: 0; padding-left: 18px; display: grid; gap: 4px; overflow-wrap: anywhere; }
  fieldset { border: none; padding: 0; margin: 0; display: grid; gap: 8px; }
  select { max-width: 100%; }
</style>
