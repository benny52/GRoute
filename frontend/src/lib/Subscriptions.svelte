<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errText, fmtDateTime, onEvent, plural, type Subscription, type SubPreview, type MergeStats } from '../api';
  import { hide, settle, ui } from '../state.svelte';
  import Help from './Help.svelte';
  import AssignmentReview from './AssignmentReview.svelte';
  import { ackSubAlert, subAlerts } from '../state.svelte'; // subinfo
  import type { SubAlert } from '../api';
  import SubInfoBar from './SubInfoBar.svelte';
  import SubscriptionReport from './SubscriptionReport.svelte';
  import { every } from '../poll';

  let { onchange }: { onchange: () => void } = $props();

  let list = $state<Subscription[]>([]);
  let url = $state('');
  let name = $state('');
  let interval = $state('24h');
  let preview = $state<SubPreview | null>(null);
  let checkedURL = $state(''); // the link preview was fetched for
  let autoName = ''; // the title check() put into name
  // The preview (and its token) belongs to the link it was fetched for: once
  // the field holds another link, «Добавить» must not add the old one.
  const shown = $derived(preview && url.trim() === checkedURL ? preview : null);
  let busy = $state('');
  let error = $state('');
  let okMsg = $state('');
  let showNames = $state(false);
  let expanded = $state('');
  const revision = $derived.by(() => {
    const s = list.find((item) => item.id === expanded);
    return s ? [s.id, s.lastUpdate, s.profiles, s.missing].join('|') : '';
  });
  const details = $derived(revision ? api.SubscriptionDetails(expanded) : null);
  let removing = $state<Subscription | null>(null);

  const intervals = [
    { v: 'manual', l: 'Вручную' },
    { v: 'startup', l: 'При запуске' },
    { v: '6h', l: 'Каждые 6 часов' },
    { v: '12h', l: 'Каждые 12 часов' },
    { v: '24h', l: 'Раз в сутки' },
  ];

  async function load() {
    try {
      list = await api.Subscriptions();
    } catch (e) {
      error = errText(e);
    }
    loaded = true;
  }
  let loaded = $state(false); // subinfo: the first load answered

  onMount(() => {
    load();
    const stop = every(load, 5000);
    // cli: an update from hyroutectl shows at once (not while this page
    // runs one of its own).
    let soon: ReturnType<typeof setTimeout> | undefined;
    const off = onEvent('status', () => {
      clearTimeout(soon);
      soon = setTimeout(() => busy === '' && load(), 300);
    });
    return () => {
      stop();
      clearTimeout(soon);
      off();
    };
  });

  async function step<T>(label: string, f: () => Promise<T>): Promise<T | undefined> {
    busy = label;
    error = '';
    okMsg = '';
    try {
      return await f();
    } catch (e) {
      error = errText(e);
    } finally {
      busy = '';
    }
  }

  async function check() {
    const u = url.trim();
    preview = null;
    const pv = await step('check', () => api.PreviewSubscription(u));
    if (pv) {
      preview = pv;
      checkedURL = u;
      // Keep a name the user typed, not the title of a previous link.
      if (!name || name === autoName) name = autoName = pv.title;
      // The interval the service advises, unless the user picked one.
      if (!intervalTouched) presetInterval(pv.updateHours);
    }
  }

  // ---- subinfo ----

  // intervalTouched: the user chose the interval in this add form; a
  // repeated «Проверить» keeps that choice. Reset with the form only.
  let intervalTouched = $state(false);
  $effect(() => {
    if (!url.trim()) intervalTouched = false;
  });

  function cancelAdd() {
    preview = null;
    intervalTouched = false;
  }

  // presetInterval applies a check's advice to an interval the user did not
  // choose. A link without advice takes back an earlier link's preset, so
  // it is not added with an interval nobody chose for it.
  let presetFrom = ''; // the interval the last advice put in the form
  function presetInterval(hours: number) {
    if (hours) {
      interval = presetFrom = intervalFor(hours);
    } else if (presetFrom && interval === presetFrom) {
      interval = '24h';
      presetFrom = '';
    }
  }

  // intervalFor is the interval bucket for the hours a service advises.
  function intervalFor(hours: number): string {
    return hours <= 6 ? '6h' : hours <= 12 ? '12h' : '24h';
  }

  // The alert of subscription id the user has not dismissed (Home, nav).
  function alertOf(id: string): SubAlert | undefined {
    return subAlerts().find((a) => a.id === id);
  }

  async function copySupport(s: Subscription) {
    if (!s.supportUrl) return;
    error = okMsg = '';
    try {
      await api.CopyText(s.supportUrl);
      okMsg = 'Ссылка поддержки скопирована.';
    } catch (e) {
      error = errText(e);
    }
  }

  // openSupport asks Go to open the panel's support link through Explorer
  // (the page never passes a URL). Explorer may hang: the button comes back
  // after 10 s even if the call has not returned. Only the latest call
  // clears the state (a hung earlier one may settle during a later one).
  let opening = $state('');
  let openingTok: object | null = null;
  async function openSupport(s: Subscription) {
    const tok = {};
    openingTok = tok;
    opening = s.id;
    error = okMsg = '';
    const t = setTimeout(() => {
      if (openingTok === tok) opening = '';
    }, 10000);
    try {
      await api.OpenSubscriptionSupport(s.id);
    } catch (e) {
      error = errText(e);
    } finally {
      clearTimeout(t);
      if (openingTok === tok) {
        opening = '';
        openingTok = null;
      }
    }
  }

  async function add() {
    const pv = shown;
    if (!pv) return;
    const v = await step('add', () => api.AddSubscription({ token: pv.token, name, enabled: true, interval }));
    if (v) {
      okMsg = `Подписка «${v.name}» добавлена: ${v.profiles} ${plural(v.profiles, 'профиль', 'профиля', 'профилей')}.`;
      url = name = '';
      preview = null;
      await load();
      onchange();
    }
  }

  function statsText(s: MergeStats): string {
    const p = [`новых ${s.added}`, `обновлено ${s.updated}`];
    if (s.removed) p.push(`удалено ${s.removed}`);
    if (s.missingKept) p.push(`оставлено с пометкой «нет в подписке» ${s.missingKept} (их используют правила)`);
    return p.join(', ');
  }

  async function update(s: Subscription) {
    const st = await step('upd:' + s.id, () => api.UpdateSubscription(s.id));
    if (st) okMsg = `«${s.name}» обновлена: ${statsText(st)}.`;
    await load();
    onchange();
  }

  async function rollback(s: Subscription) {
    if (!confirm(`Вернуть предыдущую версию подписки «${hide(s.name)}»?`)) return;
    const st = await step('rb:' + s.id, () => api.RollbackSubscription(s.id));
    if (st) okMsg = `«${s.name}»: возвращена предыдущая версия (${statsText(st)}).`;
    await load();
    onchange();
  }

  // edit reports whether the change was saved. token (a preview's) also
  // changes the link and applies what the preview downloaded. The fields
  // the patch leaves are sent as the list has them now, not as s had them:
  // changeURL calls this after a check that may take tens of seconds, and
  // the switch, interval or name changed meanwhile must not be undone.
  async function edit(s: Subscription, patch: Partial<{ name: string; token: string; enabled: boolean; interval: string }>): Promise<boolean> {
    const cur = list.find((x) => x.id === s.id) ?? s;
    const ok = await step('edit', async () => {
      await api.EditSubscription({ id: s.id, name: patch.name ?? cur.name, token: patch.token ?? '', enabled: patch.enabled ?? cur.enabled, interval: patch.interval ?? cur.interval });
      return true;
    });
    await load();
    return ok === true;
  }

  // changeURL checks the new link the way adding does before it replaces
  // the old one: the saved link is shown only masked, so a mistyped one
  // would lose it for good. The checked download is what gets applied: the
  // link is not downloaded a second time. What the check warns about (a
  // plain http:// link, links it could not parse) is shown before that, as
  // adding shows it in the preview.
  async function changeURL(s: Subscription) {
    const u = prompt(`Новая ссылка подписки «${hide(s.name)}»:`)?.trim();
    if (!u) return;
    const pv = await step('upd:' + s.id, () => api.PreviewSubscription(u));
    if (!pv) return;
    const notes = [...pv.warnings, ...pv.errors];
    if (notes.length) {
      const more = notes.length > 8 ? `\n… и ещё ${notes.length - 8}` : '';
      const found = `Найдено ${pv.count} ${plural(pv.count, 'профиль', 'профиля', 'профилей')}.`;
      if (!confirm(`${found}\n\n${notes.slice(0, 8).map(hide).join('\n')}${more}\n\nСменить ссылку подписки «${hide(s.name)}»?`)) return;
    }
    const ok = await edit(s, { token: pv.token });
    onchange();
    if (ok) {
      // The facts of the checked download; the interval stays the user's.
      okMsg = `«${s.name}»: ссылка изменена, профили обновлены.`;
      if (pv.info) okMsg += ` ${pv.info.summary}.`;
      const cur = list.find((x) => x.id === s.id) ?? s;
      if (pv.updateHours && intervalFor(pv.updateHours) !== cur.interval) okMsg += ` Сервис советует обновлять каждые ${pv.updateHours} ч.`;
    }
  }

  function rename(s: Subscription) {
    const n = prompt('Название подписки:', s.name);
    if (n && n.trim()) edit(s, { name: n.trim() });
  }

  // Proxies for the servers: a local proxy for every server of the
  // subscription, kept in step with it by HyRoute.
  let pf = $state<{ id: string; port: number; lan: boolean; username: string; password: string } | null>(null);
  let pfError = $state('');
  let pfBusy = $state(false);
  let pfCopied = $state('');

  function openProxies(s: Subscription) {
    pfError = '';
    pf = {
      id: s.id,
      port: s.proxies?.port ?? 20000,
      lan: !!s.proxies?.lan,
      username: s.proxies?.username ?? '',
      password: s.proxyPassword ?? '',
    };
  }

  function genPassword(): string {
    const a = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const b = new Uint32Array(16);
    crypto.getRandomValues(b);
    return Array.from(b, (x) => a[x % a.length]).join('');
  }

  async function saveProxies(on: boolean) {
    if (!pf) return;
    pfBusy = true;
    pfError = '';
    try {
      await api.SetSubscriptionProxies(pf.id, on ? { port: +pf.port, lan: pf.lan, username: pf.username.trim(), password: pf.password } : null);
      pf = null;
      await load();
    } catch (e) {
      pfError = errText(e);
    }
    pfBusy = false;
  }

  // copyProxies copies "name — socks5://…" for every proxy of the
  // subscription, one per line.
  async function copyProxies(s: Subscription) {
    try {
      const all = (await api.Proxies()).filter((p) => p.source === 'sub:' + s.id);
      const auth = (p: { username: string; password: string }) =>
        p.username ? `${encodeURIComponent(p.username)}:${encodeURIComponent(p.password)}@` : '';
      const lines = all.map((p) => `${p.name} — socks5://${auth(p)}127.0.0.1:${p.port}`);
      await api.CopyText(lines.join('\n'));
      pfCopied = s.id;
      setTimeout(() => (pfCopied = ''), 1500);
    } catch (e) {
      error = errText(e);
    }
  }

  async function afterRemove() {
    removing = null;
    okMsg = 'Подписка удалена.';
    await load();
    onchange();
  }

  function ignoredText(m: Record<string, number> | null): string {
    if (!m) return '';
    return Object.entries(m)
      .map(([k, v]) => `${k}: ${v}`)
      .join(', ');
  }

  function total(m: Record<string, number> | null): number {
    return m ? Object.values(m).reduce((a, b) => a + b, 0) : 0;
  }
</script>

<div class="layout">
  <header>
    <h1>Подписки</h1>
    <p class="muted sub">По ссылке от VPN-сервиса GRoute получает и обновляет список серверов.</p>
  </header>
  <Help id="subs" title="Что такое подписка">
    <p>
      Многие VPN-сервисы выдают подписку со списком своих серверов. GRoute скачивает этот
      список и обновляет его, поэтому, когда сервис добавит новый сервер или сменит старый, ничего делать не нужно.
    </p>
    <p>Вставьте ссылку ниже и нажмите «Проверить». GRoute покажет, сколько серверов нашёл. Потом нажмите «Добавить».</p>
    <p>Если сервис сообщает остаток трафика и срок подписки, они видны у подписки, а когда подходят к концу, об этом предупредит главная.</p>
  </Help>
  <section class="card">
    <h2>Добавить подписку</h2>
    <p class="muted small">
      Ссылка подписки от вашего VPN-сервиса (вида <code>https://…/sub/…</code>). GRoute получит из неё серверы
      Hysteria 2 и VLESS (список ссылок, а также конфиги Clash, sing-box и Xray) и будет обновлять их. Ссылка хранится зашифрованной и в логах не показывается.
    </p>
    <div class="row">
      <input
        class="grow mono"
        type={ui.privacy ? 'password' : 'text'}
        placeholder="https://example.com/sub/…"
        bind:value={url}
        onkeydown={(e) => e.key === 'Enter' && url.trim() && check()}
      />
      <button class="primary" onclick={check} disabled={!url.trim() || busy !== ''}>{busy === 'check' ? 'Загрузка…' : 'Проверить'}</button>
    </div>
    {#if shown}
      <div class="preview">
        <div class="big">
          Найдено {shown.count} {plural(shown.count, 'профиль', 'профиля', 'профилей')}{#if shown.ignoredTotal},
            {shown.ignoredTotal} {plural(shown.ignoredTotal, 'запись', 'записи', 'записей')} других протоколов {plural(shown.ignoredTotal, 'проигнорирована', 'проигнорированы', 'проигнорированы')}
            <span class="muted">({ignoredText(shown.ignored)})</span>{/if}.
        </div>
        {#if shown.info}<SubInfoBar info={shown.info} compact />{/if}
        {#if shown.updateHours}<div class="muted small">Сервис советует обновлять каждые {shown.updateHours} ч.</div>{/if}
        {#if shown.base64}<div class="muted small">Формат: base64-список ссылок.</div>{/if}
        {#if shown.format}<div class="muted small">Формат: конфиг {shown.format}.</div>{/if}
        <button class="link" aria-expanded={showNames} onclick={() => (showNames = !showNames)}>{showNames ? 'Скрыть подробности' : 'Показать подробности'}</button>
        {#if showNames}<SubscriptionReport report={shown.report} preview />{/if}
        {#if checkedURL.toLowerCase().startsWith('http://')}<div class="note warn small">Соединение с панелью не зашифровано. Токен подписки передаётся по HTTP.</div>{/if}
        {#if !showNames && (shown.errors.length || shown.report.warnings?.length)}<div class="note warn small">В подробностях есть замечания по импорту.</div>{/if}
        <div class="row">
          <input class="grow" placeholder="Название" bind:value={name} />
          <select bind:value={interval} title="Автообновление" onchange={() => (intervalTouched = true)}>
            {#each intervals as i}<option value={i.v}>{i.l}</option>{/each}
          </select>
          <button class="primary" onclick={add} disabled={busy !== '' || shown.count === 0}>Добавить</button>
          <button onclick={cancelAdd}>Отмена</button>
        </div>
      </div>
    {/if}
    {#if error}<div class="note error">{hide(error)}</div>{/if}
    {#if okMsg}<div class="note ok">{hide(okMsg)}</div>{/if}
  </section>

  <section class="card">
    <h2>Мои подписки</h2>
    <p class="muted small">
      Правила ссылаются на профиль по внутреннему ID, поэтому переименование серверов и смена их порядка в подписке правила не ломают.
      Если сервер пропал из подписки, а правило его использует, профиль остаётся с пометкой «нет в подписке» — трафик не
      переводится молча на другой сервер. Неудачное обновление не трогает текущий список; предыдущую версию можно вернуть.
    </p>
    {#if ui.status && !ui.status.subsOK}
      <div class="note error">Список подписок не загружен (subscriptions.json), поэтому остаток трафика и срок подписок не показываются. Подробности — в сообщении вверху окна.</div>
    {/if}
    {#if !loaded}<p class="muted">Загрузка…</p>{:else if list.length === 0 && ui.status?.subsOK !== false}<p class="muted">Подписок нет.</p>{/if}
    {#each list as s (s.id)}
      {@const alert = alertOf(s.id)}
      <div class="sub-item" class:off={!s.enabled} class:low={s.info?.level === 'low'} class:out={s.info?.level === 'out'}>
        <div class="row">
          <label class="check" title="Автообновление включено"><input type="checkbox" checked={s.enabled} onchange={(e) => settle(e, (el) => edit(s, { enabled: el.checked }), () => s.enabled)} /></label>
          <div class="grow sub-text">
            <div class="name">{hide(s.name)}</div>
            <div class="muted mono small">{hide(s.url)}</div>
          </div>
          <select value={s.interval} onchange={(e) => settle(e, (el) => edit(s, { interval: el.value }), () => s.interval)} title="Автообновление">
            {#each intervals as i}<option value={i.v}>{i.l}</option>{/each}
          </select>
        </div>
        {#if s.info}
          <div class="info-row">
            <SubInfoBar info={s.info} />
            {#if alert}<button class="ghost small-btn" title="Не показывать на главной, пока положение не изменится" onclick={() => ackSubAlert(alert)}>Скрыть предупреждение</button>{/if}
          </div>
        {/if}
        {#if s.supportUrl}
          <div class="support small">
            <span class="muted">Поддержка:</span>
            <span class="sel mono">{hide(s.supportUrl)}</span>
            <button class="ghost small-btn" onclick={() => copySupport(s)}>Скопировать</button>
            <button class="ghost small-btn" onclick={() => openSupport(s)} disabled={opening === s.id}>{opening === s.id ? 'Открывается…' : 'Открыть'}</button>
          </div>
        {/if}
        <div class="actions">
          <button onclick={() => update(s)} disabled={busy !== ''}>{busy === 'upd:' + s.id ? 'Обновление…' : 'Обновить сейчас'}</button>
          {#if s.hasPrevious}<button onclick={() => rollback(s)} disabled={busy !== ''} title="Вернуть предыдущую успешную версию">Откатить</button>{/if}
          <button onclick={() => rename(s)}>Переименовать</button>
          <button onclick={() => changeURL(s)}>Сменить ссылку</button>
          <button onclick={() => (pf?.id === s.id ? (pf = null) : openProxies(s))} title="Свой локальный прокси (SOCKS5 и HTTP) для каждого сервера подписки">
            {s.proxies ? `Прокси: ${s.proxyCount}` : 'Прокси для серверов'}
          </button>
          <button class="danger" disabled={busy !== ''} onclick={() => (removing = s)}>Удалить</button>
        </div>
        {#if s.proxies && s.proxyCount > 0}
          <div class="meta small">
            <span>Прокси для серверов: {s.proxyCount}, порты {s.proxyFrom}{s.proxyTo !== s.proxyFrom ? `–${s.proxyTo}` : ''}{s.proxies.lan ? ', доступны из локальной сети' : ''}</span>
            <button class="ghost small-btn" onclick={() => copyProxies(s)}>{pfCopied === s.id ? 'Скопировано' : 'Скопировать список'}</button>
          </div>
        {/if}
        {#if pf && pf.id === s.id}
          <div class="pf">
            <p class="muted small">
              У каждого сервера подписки будет свой порт на этом компьютере (SOCKS5 и HTTP на одном порту), начиная с первого. Новые
              серверы подписки получат прокси сами, у пропавших прокси исчезнут, порт за сервером сохраняется. Прокси работают, пока GRoute
              подключён, и каждый запускает свой сервер — при 30 серверах это 30 процессов Hysteria или Xray. Настроить или выключить
              отдельный прокси можно на странице «Прокси».
            </p>
            <div class="pf-grid">
              <label for="pf-port">Первый порт</label>
              <input id="pf-port" type="number" min="1024" max="65535" bind:value={pf.port} style="width: 120px" />
              <span></span>
              <label class="check"><input type="checkbox" bind:checked={pf.lan} /> Доступны из локальной сети (телефон, другой компьютер)</label>
              <label for="pf-user">Логин и пароль</label>
              <div class="pf-auth">
                <input id="pf-user" bind:value={pf.username} placeholder="логин" autocomplete="off" />
                <input type={ui.privacy ? 'password' : 'text'} bind:value={pf.password} placeholder="пароль" autocomplete="new-password" />
                <button
                  onclick={() => {
                    if (!pf) return;
                    if (!pf.username) pf.username = 'hyroute';
                    pf.password = genPassword();
                  }}>Придумать</button
                >
              </div>
              {#if pf.lan}
                <span></span>
                <p class="muted small">Из локальной сети — только с паролем и на портах до 49151. Windows пустит подключения только из домашней или рабочей сети.</p>
              {/if}
            </div>
            {#if pfError}<div class="note error small">{hide(pfError)}</div>{/if}
            <div class="actions">
              <button class="primary" onclick={() => saveProxies(true)} disabled={pfBusy}>{s.proxies ? 'Сохранить' : 'Включить'}</button>
              {#if s.proxies}<button class="danger" onclick={() => saveProxies(false)} disabled={pfBusy}>Выключить и удалить прокси</button>{/if}
              <button onclick={() => (pf = null)}>Отмена</button>
            </div>
          </div>
        {/if}
        <div class="meta small">
          <span>Обновлено: {fmtDateTime(s.lastUpdate)}{#if s.viaVPN} <span class="muted" title="Подписка загружена через основной сервер после неудачной попытки прямого соединения">через VPN</span>{/if}</span>
          <span>Профилей: {s.profiles}{s.missing ? ` (нет в подписке: ${s.missing})` : ''}</span>
          {#if total(s.ignored)}<span class="muted">пропущено других протоколов: {total(s.ignored)}</span>{/if}
          {#if s.enabled && s.nextAt && !s.nextAt.startsWith('0001')}<span class="muted">следующее: {fmtDateTime(s.nextAt)}</span>{/if}
          <button class="link" aria-expanded={expanded === s.id} onclick={() => (expanded = expanded === s.id ? '' : s.id)}>{expanded === s.id ? 'Скрыть подробности' : 'Показать подробности'}</button>
        </div>
        {#if expanded === s.id && details}
          {#await details}
            <p class="muted small">Загрузка подробностей…</p>
          {:then report}
            <SubscriptionReport {report} />
          {:catch err}
            <p class="note error small">{hide(errText(err))}</p>
          {/await}
        {/if}
        {#if s.lastError}<div class="note error small">Последняя ошибка ({fmtDateTime(s.lastAttempt)}): {hide(s.lastError)}. Профили не изменены.</div>{/if}
        {#if s.errorCount}
          <div class="note warn small">
            При последнем обновлении не разобрано {s.errorCount} {plural(s.errorCount, 'ссылка', 'ссылки', 'ссылок')}: их серверов нет в списке.
          </div>
        {/if}
        {#if s.warnings?.length && expanded !== s.id}<div class="note warn small">Подробности содержат предупреждения импорта.</div>{/if}
      </div>
    {/each}
  </section>
</div>

{#if removing}
  <AssignmentReview request={{ operation: 'deleteSubscription', subscriptionId: removing.id }}
    title={`Удалить подписку «${hide(removing.name)}»?`} confirmLabel="Удалить подписку"
    onclose={() => (removing = null)} onapplied={afterRemove} />
{/if}

<style>
  .layout { display: grid; gap: 16px; max-width: 1000px; }
  .sub { margin: 4px 0 0; }
  .small { font-size: 12px; }
  p.small { margin: 0 0 10px; }
  code { font-family: var(--mono); font-size: 12px; }
  .preview { margin-top: 10px; padding: 10px 12px; border: 1px solid var(--border); border-radius: 6px; display: grid; gap: 6px; }
  .big { font-weight: 600; }
  .link { background: none; border: none; padding: 0; color: var(--accent); cursor: pointer; justify-self: start; }
  .sub-item { border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 10px 12px; margin-bottom: 8px; }
  .sub-item.off { opacity: 0.7; }
  .sub-item.low { border-color: color-mix(in srgb, var(--warn) 55%, var(--border)); }
  .sub-item.out { border-color: color-mix(in srgb, var(--block) 55%, var(--border)); }
  .info-row { display: flex; flex-wrap: wrap; align-items: flex-start; gap: 8px 12px; margin: 8px 0 0 30px; }
  .info-row :global(.subinfo) { flex: 1; }
  .support { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 8px; margin: 6px 0 0 30px; min-width: 0; }
  .sel { user-select: text; overflow-wrap: anywhere; min-width: 0; }
  .small-btn { padding: 3px 8px; font-size: 12px; }
  .sub-text { min-width: 0; }
  .actions { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0 0 30px; }
  .name { font-weight: 600; }
  .meta { display: flex; flex-wrap: wrap; gap: 4px 16px; margin: 6px 0 0 30px; }
  .note.small { margin: 6px 0 0; }
  .pf { margin: 8px 0 0 30px; padding: 10px 12px; border: 1px solid var(--border); border-radius: var(--radius-sm); display: grid; gap: 8px; }
  .pf p { margin: 0; }
  .pf .actions { margin: 0; }
  .pf-grid { display: grid; grid-template-columns: 130px minmax(0, 1fr); gap: 8px 12px; align-items: center; }
  .pf-auth { display: flex; gap: 6px; }
  .pf-auth input { flex: 1; min-width: 0; }
</style>
