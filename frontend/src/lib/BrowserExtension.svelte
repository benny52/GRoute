<script lang="ts">
  // «Настройки» → «Расширение для браузера»: the extension's files, the
  // link to the browsers and the switch that lets it in.
  import { onMount } from 'svelte';
  import { api, errText, type BrowserExtView } from '../api';
  import { ui, hide, settle } from '../state.svelte';
  import Icon from './Icon.svelte';
  import BrowserPageFallback from './BrowserPageFallback.svelte';

  let view = $state<BrowserExtView | null>(null);
  let error = $state('');
  let ok = $state('');
  let busy = $state(false);
  let chosen = $state('');
  let failedBrowser = $state('');
  const browsers = $derived(view?.browsers?.filter((browser) => browser.exe) ?? []);
  const browser = $derived(browsers.find((b) => b.id === chosen) ?? browsers[0]);

  async function load() {
    try {
      view = await api.BrowserExtInfo();
    } catch (e) {
      error = errText(e);
    }
  }

  // Re-read when the window comes back: the user was in the browser.
  onMount(() => {
    load();
    const soon = () => load();
    window.addEventListener('focus', soon);
    return () => window.removeEventListener('focus', soon);
  });

  async function run(f: () => Promise<BrowserExtView | void>, done: string) {
    error = '';
    ok = '';
    busy = true;
    try {
      const v = await f();
      if (v) view = v;
      ok = done;
    } catch (e) {
      error = errText(e);
      await load();
    } finally {
      busy = false;
    }
  }

  const install = () => run(() => api.InstallBrowserExt(), 'Готово. Осталось добавить расширение в браузер: шаги ниже.');
  function open() {
    if (!view || !browser || busy) return;
    const id = browser.id;
    failedBrowser = '';
    const prepare = !view.installed || !browser.linked;
    return run(async () => {
      if (prepare) view = await api.InstallBrowserExt();
      try {
        await api.OpenBrowserExtensions(id);
      } catch (e) {
        failedBrowser = id;
        throw e;
      }
    }, 'Страница расширений открыта.');
  }
  const remove = () =>
    confirm('Отвязать браузеры от GRoute и удалить папку расширения? Само расширение уберите на странице расширений браузера.') &&
    run(() => api.RemoveBrowserExt(), 'Связь с браузерами удалена.');

  async function copyDir() {
    if (view) await run(() => api.CopyText(view!.dir), 'Скопировано');
  }

  function seenText(t: number): string {
    if (!t) return 'с запуска GRoute расширение ещё не обращалось';
    const min = Math.round((Date.now() / 1000 - t) / 60);
    if (min < 1) return 'расширение обращалось только что';
    if (min < 60) return `расширение обращалось ${min} мин назад`;
    return `расширение обращалось ${Math.round(min / 60)} ч назад`;
  }

  // The folder may carry the user's name: masked in Privacy mode.
  function hidePath(p: string): string {
    if (!ui.privacy) return p;
    return hide(p.replace(/([\\/]Users[\\/])[^\\/]+/i, '$1***'));
  }
</script>

<section class="card">
  <h2><Icon name="globe" size={17} /> Расширение для браузера</h2>
  <p class="muted small">
    Кнопка GRoute в Chrome, Edge, Яндекс Браузере, Brave, Opera и Vivaldi. Показывает адреса открытой страницы (и какие не загрузились) и как
    GRoute их отправляет, а одним нажатием отправляет весь сайт через VPN или отмеченные адреса — через VPN, напрямую или в блок. У каждого сайта своё правило «Из браузера: сайт» в начале
    {ui.expert ? 'активного профиля правил' : 'списка правил'}.{#if ui.expert}
      Связь с GRoute — через {ui.portable ? 'groute-browser-host.exe' : ui.mac ? 'hyroutectl' : 'hyroutectl.exe'}, без открытых портов; список адресов страницы хранится только в памяти браузера.{/if}
  </p>
  {#if !view && !error}<p class="muted small">Загрузка…</p>{/if}
  {#if view}
    {#if !view.host}
      {#if ui.mac}
        <div class="note warn small">hyroutectl не установлен: откройте новую версию GRoute.app, она обновит службу.</div>
      {:else}
        <div class="note warn small">В комплекте GRoute отсутствует {ui.portable ? 'browser/groute-browser-host.exe' : 'hyroutectl.exe'}. Распакуйте полный комплект программы.</div>
      {/if}
    {/if}
    {#if browser}
      <div class="picker">
        <label>Браузер
          <select value={browser.id} onchange={(e) => { chosen = e.currentTarget.value; failedBrowser = error = ok = ''; }} disabled={busy}>
            {#each browsers as b (b.id)}<option value={b.id}>{b.name}</option>{/each}
          </select>
        </label>
        <button class="primary" disabled={busy || !view.host} onclick={open}><Icon name="globe" size={15} /> Открыть страницу расширений</button>
      </div>
      {#if failedBrowser === browser.id && browser.page && view.installed}
        <BrowserPageFallback page={browser.page} />
      {/if}
      {#if !view.installed || !browser.linked}
        <p class="muted small">При открытии GRoute подготовит файлы и разрешит расширению смотреть и менять правила.</p>
      {/if}
    {:else}
      <p class="muted small">Поддерживаемые браузеры не найдены. Если браузер установлен в другой папке, добавьте расширение через меню управления расширениями в самом браузере.</p>
      {#if !view.installed}<button disabled={busy || !view.host} onclick={install}>Подготовить файлы расширения</button>{/if}
    {/if}
    <p class="muted small">В браузере включите «Режим разработчика», нажмите «Загрузить распакованное расширение» и выберите папку расширения.</p>
    {#if view.installed}
      <label class="check">
        <input type="checkbox" checked={view.on} disabled={busy}
          onchange={(e) => settle(e, (el) => run(() => api.SetBrowserExtOn(el.checked), el.checked ? 'Расширение включено' : 'Расширение выключено'), () => view?.on ?? false)} />
        Расширение может смотреть и менять правила
      </label>
      <p class="muted small">{view.on ? seenText(view.seen) : 'Выключено: расширение покажет, что GRoute его не пускает.'}</p>

      <h3>Папка расширения</h3>
      <div class="row wrap">
        <code class="grow path">{hidePath(view.dir)}</code>
        {#if !ui.mac}<button onclick={() => run(() => api.OpenBrowserExtensionFolder(), '')} disabled={busy}>Показать папку</button>{/if}
        <button onclick={copyDir} disabled={busy}><Icon name="copy" size={15} /> Скопировать путь к папке</button>
      </div>
      <p class="muted small">
        {#if ui.portable}
          Папка расширения находится в профиле Windows. После переноса GRoute в другую папку браузер продолжит использовать её.
          Для обновления расширения нажмите «Установить заново», затем «Обновить» на странице расширений браузера.
        {:else}
          Браузер подхватит новые файлы после перезапуска или кнопки «Обновить» на странице расширений.
        {/if}
      </p>
      <div class="row wrap">
        <button disabled={busy || !view.host} onclick={install}><Icon name="refresh" size={15} /> Установить заново</button>
        <button class="danger" disabled={busy} onclick={remove}><Icon name="trash" size={15} /> Удалить связь с браузерами</button>
      </div>
    {/if}
  {/if}
  {#if error}<div class="note error small">{hide(error)}</div>{/if}
  {#if ok}<p class="muted small">{ok}</p>{/if}
</section>

<style>
  h3 {
    margin: 12px 0 4px;
    font-size: 13px;
  }
  .picker {
    display: flex;
    align-items: flex-end;
    flex-wrap: wrap;
    gap: 8px;
    margin: 10px 0;
  }
  .picker label {
    display: grid;
    gap: 4px;
    min-width: min(180px, 100%);
    font-size: 13px;
  }
  .path {
    overflow-wrap: anywhere;
    user-select: all;
  }
  .wrap {
    flex-wrap: wrap;
  }
</style>
