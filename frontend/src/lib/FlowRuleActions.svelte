<script module lang="ts">
  import type { Flow } from '../api';
  export interface FlowMenu {
    flow: Flow;
    anchor: { x: number; y: number };
    el: HTMLElement | null;
    appOnly?: boolean;
    choices?: Flow[];
  }
</script>

<script lang="ts">
  import { api, cleanRule, type Rule, type ConnFacts } from '../api';
  import { mainTarget, hide } from '../state.svelte';
  import { ruleTitle } from '../ruletitle';
  import ConnMenu, { showConnResult } from './ConnMenu.svelte';
  import RuleEditor from './RuleEditor.svelte';
  import Explain from './Explain.svelte';
  let { menu = $bindable() }: { menu: FlowMenu | null } = $props();
  let draft = $state<{ rule: Rule; facts: ConnFacts; ruleset: string; udp: boolean } | null>(null);
  let explainQ = $state<{ app: string; target: string; proto: string; port: number; note: string; observed: Flow } | null>(null);
  // explainRet: the element that gets the focus back when «Проверить адрес»
  // closes.
  let explainRet: HTMLElement | null = null;
  let explainEl = $state<HTMLElement>();

  $effect(() => {
    if (explainQ && explainEl) explainEl.focus();
  });

  function closeExplain() {
    explainQ = null;
    if (explainRet?.isConnected) explainRet.focus();
    explainRet = null;
  }

  async function saveDraft(r: Rule) {
    const d = draft!;
    const res = await api.AddConnRule({ facts: d.facts, rule: cleanRule(r, mainTarget()?.id), source: 'editor', ruleset: d.ruleset });
    draft = null;
    const saved = res.rule;
    showConnResult(res, () => hide(ruleTitle(saved)), d.udp);
  }

</script>

{#if menu}
  {#key menu.flow}
    <ConnMenu
      flow={menu.flow}
      anchor={menu.anchor}
      appOnly={menu.appOnly}
      choices={menu.choices}
      onchoose={(flow) => { if (menu) menu = { ...menu, flow }; }}
      returnFocus={menu?.el ?? null}
      onclose={() => (menu = null)}
      onedit={(rule, facts, ruleset) => (draft = { rule, facts, ruleset, udp: facts.proto.toLowerCase() === 'udp' })}
      onexplain={(q) => {
        explainRet = menu?.el ?? null;
        if (menu) explainQ = { ...q, observed: menu.flow };
      }}
    />
  {/key}
{/if}

{#if draft}
  <RuleEditor rule={draft.rule} title="Новое правило из соединения" onsave={saveDraft} onclose={() => (draft = null)} />
{/if}

{#if explainQ}
  <div
    class="backdrop"
    role="presentation"
    onclick={(e) => e.target === e.currentTarget && closeExplain()}
    onkeydown={(e) => e.key === 'Escape' && closeExplain()}
  >
    <div class="dialog explain" role="dialog" aria-label="Проверить адрес" tabindex="-1" bind:this={explainEl}>
      <Explain initial={explainQ} current={() => null} onclose={closeExplain} />
    </div>
  </div>
{/if}

<style>
  .explain { width: min(820px, 94vw); padding: 0; }
</style>
