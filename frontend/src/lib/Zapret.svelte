<script lang="ts">
  // «Обход DPI»: YouTube, Discord and the user's sites without a VPN,
  // through zapret2's winws2 (internal/app/zapret.go). One switch, ticks and
  // «Подобрать автоматически»; the methods are for the full interface.
  import { onMount } from 'svelte';
  import { api, errText, onEvent, type ZapretTarget, type ZapretView } from '../api';
  import { ui, hide } from '../state.svelte';
  import Icon from './Icon.svelte';
  import ZapretVPN from './ZapretVPN.svelte';

  let { go }: { go: (page: string) => void } = $props();

  let view = $state<ZapretView | null>(null);
  let error = $state('');
  let saved = $state('');
  let vpnFor = $state<ZapretTarget | null>(null); // «Пустить … через VPN»: the choice is open
  let saving = $state(false);
  let picking = $state(false);
  // The form (what is saved).
  let enabled = $state(false);
  let targets = $state<ZapretTarget[]>([]);
  let sitesText = $state('');
  let methods = $state<Partial<Record<ZapretTarget, string>>>({});
  let loaded = false;

  const hints: Record<ZapretTarget, string> = {
    youtube: 'сайт, приложение и видео (googlevideo)',
    discord: 'сайт, программа, голос и демонстрация экрана',
    sites: 'сайты, которые вы перечислите',
  };

  async function refresh() {
    try {
      const v = await api.ZapretInfo();
      view = v;
      if (!loaded) {
        loaded = true;
        enabled = v.settings.enabled;
        targets = [...(v.settings.targets ?? [])];
        sitesText = (v.settings.sites ?? []).join('\n');
        methods = { ...(v.settings.methods ?? {}) };
      }
    } catch (e) {
      error = errText(e);
    }
  }

  onMount(() => {
    refresh();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const off = onEvent('status', () => {
      if (timer) return;
      timer = setTimeout(() => {
        timer = undefined;
        refresh();
      }, 700);
    });
    return () => {
      off();
      if (timer) clearTimeout(timer);
    };
  });

  const sites = $derived(
    sitesText
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean),
  );
  const dirty = $derived.by(() => {
    if (!view) return false;
    const s = view.settings;
    return (
      s.enabled !== enabled ||
      JSON.stringify([...(s.targets ?? [])].sort()) !== JSON.stringify([...targets].sort()) ||
      (s.sites ?? []).join('\n') !== sites.join('\n') ||
      JSON.stringify(s.methods ?? {}) !== JSON.stringify(Object.fromEntries(Object.entries(methods).filter(([, m]) => m)))
    );
  });

  function toggle(t: ZapretTarget, on: boolean) {
    targets = on ? [...targets.filter((x) => x !== t), t] : targets.filter((x) => x !== t);
  }

  async function save() {
    error = saved = '';
    saving = true;
    try {
      const m = Object.fromEntries(Object.entries(methods).filter(([, v]) => v));
      await api.SaveZapret({ enabled, targets, sites, methods: m });
      loaded = false;
      await refresh();
      saved = enabled ? 'Сохранено, обход работает с новыми настройками' : 'Обход выключен';
    } catch (e) {
      error = errText(e);
    }
    saving = false;
  }

  // viaVPN sends one service through the VPN (or back to the bypass) and
  // saves at once: the rest of the form stays as saved.
  async function viaVPN(t: ZapretTarget, on: boolean) {
    if (!view) return;
    error = saved = '';
    const st = view.settings;
    const m = { ...(st.methods ?? {}) };
    if (on) m[t] = 'vpn';
    else delete m[t];
    try {
      await api.SaveZapret({ enabled: st.enabled, targets: st.targets ?? [], sites: st.sites ?? [], methods: m });
      loaded = false;
      await refresh();
      const name = view?.targets.find((x) => x.target === t)?.name ?? t;
      saved = on ? `${name} теперь идёт через VPN` : `${name} снова идёт через обход`;
    } catch (e) {
      error = errText(e);
    }
  }

  // «Telegram без VPN»: saved at once, apart from the form above.
  let tgBusy = $state(false);
  let tgError = $state('');
  let tgPort = $state(1443);
  let tgNote = $state('');
  $effect(() => {
    if (view && !tgBusy) tgPort = view.telegram.port;
  });
  async function saveTelegram(on: boolean) {
    tgBusy = true;
    tgError = '';
    try {
      await api.SaveTelegram({ enabled: on, port: Number(tgPort) || 0 });
      loaded = false;
      await refresh();
    } catch (e) {
      tgError = errText(e);
      await refresh();
    }
    tgBusy = false;
  }
  async function openTelegram() {
    tgError = '';
    try {
      await api.OpenTelegramProxy();
    } catch (e) {
      tgError = errText(e);
    }
  }
  async function copyTelegram() {
    const l = view?.telegram.link;
    if (!l) return;
    try {
      await api.CopyText(l);
      tgNote = 'Ссылка скопирована: отправьте её себе в Telegram и нажмите на неё';
    } catch (e) {
      tgError = errText(e);
    }
  }

  // setHeal turns self-healing on or off at once (the rest as saved).
  async function setHeal(on: boolean) {
    if (!view) return;
    error = saved = '';
    const st = view.settings;
    try {
      await api.SaveZapret({ enabled: st.enabled, targets: st.targets ?? [], sites: st.sites ?? [], methods: st.methods ?? {}, autoHeal: on });
      loaded = false;
      await refresh();
    } catch (e) {
      error = errText(e);
    }
  }

  const clock = (ms: number) => new Date(ms).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });

  async function pick() {
    error = saved = '';
    picking = true;
    // The pick takes up to a few minutes: the page follows its progress.
    const poll = setInterval(refresh, 1000);
    try {
      view = await api.ZapretPick();
    } catch (e) {
      error = errText(e);
      await refresh();
    }
    clearInterval(poll);
    picking = false;
  }

  const running = $derived(view?.status.state === 'running');
  const pickNow = $derived(view?.pick?.running ? view.pick : null);
  function resultText(t: ZapretTarget): string {
    const m = view?.pick?.results[t];
    if (m === 'none') return 'не блокируется — обход не нужен';
    if (!m) return view?.pick?.diagnosis?.[t]?.bypass === false ? 'обход тут не поможет' : 'ни один метод не открыл';
    const spare = (view?.pick?.working?.[t]?.length ?? 1) - 1;
    const name = view?.methods.find((x) => x.id === m)?.name ?? m;
    return `быстрее всех открывает «${name}»` + (spare > 0 ? `; если перестанет, есть ещё ${spare} ${spare === 1 ? 'рабочий метод' : spare < 5 ? 'рабочих метода' : 'рабочих методов'}` : '');
  }
  const viaVPNNow = (t: ZapretTarget) => view?.settings.methods?.[t] === 'vpn';
  // How many of the working strategies the generator made (not the library).
  const genFound = $derived(
    new Set(Object.values(view?.pick?.working ?? {}).flatMap((ws) => (ws ?? []).filter((id) => id.startsWith('g:')))).size,
  );
</script>

<div class="page">
  <header>
    <h1>Обход DPI</h1>
    <p class="muted">
      YouTube, Discord и другие сайты без VPN: HyRoute запускает zapret2, который обманывает блокировку провайдера. Трафик идёт напрямую, не тратит
      трафик серверов и не замедляется ими.
    </p>
  </header>

  {#snippet telegramCard(v: ZapretView)}
    {@const tg = v.telegram}
    {@const r = tg.stats.routes ?? {}}
    <section class="card">
      <h2>Telegram без VPN</h2>
      <p class="muted small">
        Telegram ходит к своим серверам через WebSocket веб-версии — их блокируют редко. Когда HyRoute подключён, он перехватывает Telegram сам (и его
        форки, например AyuGram): ничего настраивать не нужно. Без подключения Telegram идёт через прокси HyRoute — его нужно один раз добавить в
        Telegram. Если WebSocket не отвечает, Telegram идёт через ваш сервер VPN или напрямую. Звонки так не идут.
      </p>
      <label class="switch">
        <input type="checkbox" checked={tg.enabled} disabled={tgBusy} onchange={(e) => saveTelegram(e.currentTarget.checked)} />
        <b>Включить</b>
      </label>
      {#if tg.enabled && tg.health}
        {@const h = tg.health}
        {#if h.ws}
          <div class="small using">
            ✓ Telegram отвечает через WebSocket{h.wsRoute === 'ws-fronted' ? ' (под другим именем: прямое заблокировано)' : ''}, {h.wsMillis} мс · проверено
            {clock(Date.parse(h.at))}
          </div>
        {:else if h.fallback}
          <div class="note info small">
            WebSocket сейчас не отвечает — Telegram идёт {h.fallback === 'vpn' ? 'через ваш сервер VPN' : 'напрямую к серверам Telegram'}. HyRoute
            проверяет снова каждые 5 минут и вернётся к WebSocket, когда он заработает. <span class="faint">({hide(h.wsError)})</span>
          </div>
        {:else}
          <div class="note error small">
            Telegram не отвечает ни через WebSocket, ни {tg.intercepted ? 'через VPN, ни ' : ''}напрямую.
            {tg.intercepted ? 'Проверьте интернет и сервер VPN.' : 'Подключите HyRoute к серверу VPN: тогда Telegram пойдёт через него.'}
            <span class="faint">({hide(h.wsError ?? '')}{h.fallbackError ? '; ' + hide(h.fallbackError) : ''})</span>
          </div>
        {/if}
      {/if}
      {#if tg.enabled}
        <div class="small">
          {#if tg.intercepted}
            HyRoute подключён: Telegram идёт сюда сам, прокси в Telegram не нужен.
          {:else}
            HyRoute не подключён: Telegram идёт сюда, только если в нём добавлен прокси HyRoute.
          {/if}
        </div>
      {/if}
      {#if tg.error}<div class="note error small">{tg.error}</div>{/if}
      {#if tg.running}
        <div class="row">
          <button class="primary" onclick={openTelegram}><Icon name="arrow" size={15} />Подключить Telegram</button>
          <button onclick={copyTelegram}><Icon name="copy" size={15} />Скопировать ссылку</button>
        </div>
        <p class="muted small">
          Один раз: Telegram спросит, подключить ли прокси, — согласитесь. Дальше он работает сам, пока HyRoute запущен. Если Telegram не открылся,
          скопируйте ссылку, отправьте её себе в «Избранное» и нажмите на неё.
        </p>
        {#if tg.stats.total > 0}
          <div class="small">
            Соединений сейчас: {tg.stats.active}. Всего: через WebSocket {(r['ws'] ?? 0) + (r['ws-fronted'] ?? 0)}, через VPN {r['vpn'] ?? 0}, напрямую
            {r['tcp'] ?? 0}{tg.stats.failed ? `, не открылось ${tg.stats.failed}` : ''}.
          </div>
        {/if}
        {#if tg.stats.bad > 0}<div class="note error small">Telegram подключается с неверным секретом: удалите старый прокси в Telegram и нажмите «Подключить Telegram».</div>{/if}
        {#if tg.stats.lastError}<div class="muted small">Последняя ошибка: {hide(tg.stats.lastError)}</div>{/if}
      {/if}
      {#if ui.expert}
        <label class="lbl" for="tg-port">Порт прокси (127.0.0.1)</label>
        <input id="tg-port" type="number" min="1024" max="65535" bind:value={tgPort} onchange={() => saveTelegram(tg.enabled)} />
      {/if}
      {#if tgError}<div class="note error small">{hide(tgError)}</div>{/if}
      {#if tgNote && !tgError}<div class="note ok small">{tgNote}</div>{/if}
    </section>
  {/snippet}

  {#if view && !view.available}
    <div class="note info">Обход DPI (zapret2) пока работает только на Windows.</div>
    {@render telegramCard(view)}
  {:else if view}
    {#if view.loadError}<div class="note error">{view.loadError}</div>{/if}

    <section class="card">
      <label class="switch">
        <input type="checkbox" bind:checked={enabled} />
        <b>Обходить блокировки без VPN</b>
      </label>
      <div class="tiles">
        {#each view.targets as t (t.target)}
          <label class="tile" class:on={targets.includes(t.target)}>
            <input type="checkbox" checked={targets.includes(t.target)} disabled={!enabled} onchange={(e) => toggle(t.target, e.currentTarget.checked)} />
            <span class="grow">
              <b>{t.name}</b>
              <span class="muted small">{hints[t.target]}</span>
              {#if t.on && enabled}<span class="small using">Сейчас: {t.using}</span>{/if}
              {#if t.on && enabled && viaVPNNow(t.target) && !dirty}
                <button class="link small" onclick={(e) => { e.preventDefault(); viaVPN(t.target, false); }}>Вернуть обход</button>
                <button class="link small" onclick={(e) => { e.preventDefault(); vpnFor = t.target; }}>Сервер…</button>
              {/if}
            </span>
          </label>
        {/each}
      </div>
      {#if enabled && targets.includes('sites')}
        <label class="lbl" for="zp-sites">Свои сайты — по одному на строку: имя (поддомены включаются сами), IP или подсеть</label>
        <textarea id="zp-sites" rows="4" class:masked={ui.privacy} bind:value={sitesText} placeholder={'example.com\n203.0.113.7\n198.51.100.0/24'}></textarea>
        <span class="muted small">Подбор проверяет только имена, адреса получают те же методы.</span>
      {/if}

      {#if ui.expert && enabled && targets.length}
        <div class="lbl">Метод для каждого сервиса</div>
        <div class="methods">
          {#each view.targets.filter((t) => targets.includes(t.target)) as t (t.target)}
            <label class="mrow"
              ><span>{t.name}</span>
              <select bind:value={methods[t.target]}>
                <option value="">Автоматически (перебор, если перестал работать)</option>
                {#each view.methods.filter((m) => !m.generated) as m (m.id)}<option value={m.id}>{m.name}</option>{/each}
                {#if view.methods.some((m) => m.generated)}
                  <optgroup label="Найдены генератором в этой сети">
                    {#each view.methods.filter((m) => m.generated) as m (m.id)}<option value={m.id}>{m.name}</option>{/each}
                  </optgroup>
                {/if}
                <option value="none">Не нужен</option>
                <option value="vpn">Через VPN</option>
              </select></label
            >
          {/each}
        </div>
      {/if}

      <div class="row">
        <button class="primary" onclick={save} disabled={saving || !dirty || (enabled && targets.length === 0)}>{saving ? 'Сохраняю…' : 'Сохранить'}</button>
        {#if view.busy}<span class="muted small">{view.busy}</span>{/if}
      </div>
      {#if error}<div class="note error">{hide(error)}</div>{/if}
      {#if saved && !error}<div class="note ok small">{saved}</div>{/if}

      {#if view.settings.enabled}
        <div class="state">
          {#if view.prepareError}
            <div class="note error small">{view.prepareError}</div>
          {:else if running}
            <span class="dot ok"></span> zapret2 работает
          {:else if view.status.state === 'error'}
            <div class="note error small">{view.status.error}. HyRoute запустит его снова.</div>
          {:else if !view.busy}
            <span class="dot"></span>
            <span class="muted">zapret2 не запущен: на этой сети обход не нужен или ещё не настроен</span>
          {/if}
        </div>
      {/if}
    </section>

    {#if view.settings.enabled && (view.settings.targets ?? []).length}
      <section class="card">
        <h2>Подобрать метод</h2>
        <p class="muted small">
          У каждого провайдера работают свои методы. HyRoute выяснит, как именно блокируется каждый сервис, попробует известные методы, а потом
          сам соберёт и проверит десятки своих вариантов: рядом с теми, что сработали, а если не сработало ничего — по всем приёмам zapret2 и с фейками
          сайтов из белого списка. Для этой сети{view.network ? ` («${hide(view.network)}»)` : ''} запомнит самый быстрый и запасные. Займёт от полуминуты до
          трёх минут; обход при этом продолжает работать.
        </p>
        {#if pickNow}
          <div class="progress"><div class="bar" style="width: {Math.round((100 * pickNow.done) / Math.max(1, pickNow.total))}%"></div></div>
          {#if pickNow.auto}<div class="small using">Подбираю сам: {pickNow.why}</div>{/if}
          <div class="small">{pickNow.step}</div>
          <button onclick={() => api.ZapretPickCancel()}>Остановить</button>
        {:else}
          <button class="primary" onclick={pick} disabled={picking || dirty}>
            <Icon name="zap" size={15} />{picking ? 'Подбираю…' : 'Подобрать автоматически'}
          </button>
          {#if dirty}<span class="muted small">Сначала сохраните изменения.</span>{/if}
        {/if}
        <label class="check heal">
          <input type="checkbox" checked={view.settings.autoHeal !== false} disabled={dirty} onchange={(e) => setHeal(e.currentTarget.checked)} />
          <span
            >Следить и подбирать заново самому
            <span class="muted small"
              >— раз в 10 минут HyRoute открывает сервисы через обход. Если сервис перестал открываться, а блокировку можно обойти, подберёт метод
              заново сам; на новой сети — тоже. Если не открывается и без обхода (нет интернета, блок по адресу), ничего не трогает.</span
            ></span
          >
        </label>
        {#if view.healNote && view.settings.autoHeal !== false}<div class="muted small">{view.healAt ? `${clock(view.healAt)}: ` : ''}{hide(view.healNote)}</div>{/if}
        {#if view.pick && !view.pick.running}
          {#if view.pick.error}
            <div class="note error small">{hide(view.pick.error)}</div>
          {:else}
            {#if view.pick.tried}<div class="muted small tried">Проверено вариантов: {view.pick.tried}{#if genFound > 0}, из них свои, собранные генератором, рабочие: {genFound}{/if}.</div>{/if}
            <ul class="results">
              {#each view.targets.filter((t) => t.target in (view?.pick?.results ?? {})) as t (t.target)}
                {@const d = view.pick.diagnosis?.[t.target]}
                {@const res = view.pick.results[t.target]}
                <li>
                  <b>{t.name}</b>: {resultText(t.target)}
                  {#if d && res !== 'none'}<div class="muted small">Без обхода: {d.text} <span class="faint">({hide(d.detail)})</span></div>{/if}
                  {#if !res}
                    <div class="vpn">
                      {#if d && !d.bypass}
                        <span class="small">Такую блокировку обходит только VPN.</span>
                      {:else}
                        <span class="small">Провайдер блокирует сильнее, чем умеют эти методы.</span>
                      {/if}
                      {#if viaVPNNow(t.target)}
                        <span class="small using">{t.name} уже идёт через VPN.</span>
                      {:else if view.hasServer}
                        <button class="primary small-btn" onclick={() => (vpnFor = t.target)} disabled={dirty}>Пустить {t.name} через VPN</button>
                      {:else}
                        <span class="small muted">Добавьте сервер VPN, и HyRoute сможет пустить {t.name} через него.</span>
                      {/if}
                    </div>
                  {/if}
                </li>
              {/each}
            </ul>
            {#if view.pick.skipped?.length}
              <div class="muted small tried">
                Не проверялись — не открываются и без обхода, обход им не поможет: {hide(view.pick.skipped.join('; '))}. Проверьте адрес; если сайт
                заблокирован по адресу, нужен VPN.
              </div>
            {/if}
          {/if}
        {/if}
      </section>
    {/if}

    {@render telegramCard(view)}

    <section class="card info">
      <p class="small">
        HyRoute держит правила «Обход DPI: …» наверху профиля правил: этот трафик идёт напрямую, через обход, а не через VPN. Если обход сервису не
        помогает, подбор предложит пустить его через VPN; снимите сервис здесь, и он пойдёт по вашим обычным правилам.
        {#if ui.expert}<button class="link" onclick={() => go('rules')}>Правила</button>{/if}
      </p>
      <p class="small muted">
        zapret2 (bol-van/zapret2) скачивается с GitHub при первом включении и проверяется по контрольным суммам. Антивирусы иногда ругаются на winws2 и
        WinDivert: это ложная тревога, они перехватывают сетевые пакеты, как и сам HyRoute.
      </p>
    </section>

    {#if ui.expert && view.commandLine}
      <details class="card">
        <summary>Командная строка и журнал winws2</summary>
        <pre class="mono small">{hide(view.commandLine)}</pre>
        {#if view.status.lines.length}<pre class="mono small">{hide(view.status.lines.join('\n'))}</pre>{/if}
      </details>
    {/if}
  {/if}
</div>

{#if vpnFor}
  <ZapretVPN
    target={vpnFor}
    onclose={() => (vpnFor = null)}
    ondone={async (msg) => {
      vpnFor = null;
      error = '';
      loaded = false;
      await refresh();
      saved = msg;
    }}
  />
{/if}

<style>
  .page { display: grid; gap: 14px; }
  header h1 { margin: 0 0 4px; }
  .switch { display: flex; align-items: center; gap: 10px; font-size: 15px; }
  .tiles { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px; margin-top: 12px; }
  .tile { display: flex; gap: 10px; align-items: flex-start; padding: 10px 12px; border: 1px solid var(--border); border-radius: var(--radius-sm); cursor: pointer; }
  .tile.on { border-color: color-mix(in srgb, var(--accent) 55%, var(--border)); background: var(--accent-soft); }
  .tile .grow { display: grid; gap: 2px; min-width: 0; }
  .using { color: var(--accent); }
  .lbl { display: block; color: var(--muted); font-weight: 500; margin-top: 12px; }
  textarea { width: 100%; box-sizing: border-box; margin-top: 4px; }
  .methods { display: grid; gap: 6px; margin-top: 4px; }
  .mrow { display: grid; grid-template-columns: 110px minmax(0, 1fr); gap: 8px; align-items: center; }
  .row { display: flex; align-items: center; gap: 10px; margin-top: 12px; flex-wrap: wrap; }
  .state { margin-top: 10px; display: flex; align-items: center; gap: 8px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--faint); flex: none; }
  .dot.ok { background: var(--direct); }
  .progress { height: 6px; border-radius: 3px; background: var(--surface-2); overflow: hidden; margin: 8px 0 4px; }
  .bar { height: 100%; background: var(--accent); transition: width 0.3s; }
  .tried { margin-top: 8px; }
  .heal { display: flex; gap: 8px; align-items: flex-start; margin-top: 12px; }
  .heal input { margin-top: 3px; flex: none; }
  .results { margin: 8px 0 0; padding-left: 18px; display: grid; gap: 6px; }
  .vpn { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-top: 4px; }
  .small-btn { padding: 4px 10px; font-size: 13px; }
  pre { white-space: pre-wrap; word-break: break-all; margin: 8px 0 0; }
  h2 { margin: 0 0 6px; }
  textarea.masked { -webkit-text-security: disc; }
</style>
