import { api, errText, formatResponseMs } from '../api';

export const batch = $state({
  running: false, done: 0, total: 0,
  states: {} as Record<string, 'queued' | 'checking'>,
  stopping: false, cancelled: false, error: '',
  results: {} as Record<string, { ok: boolean; label: string }>,
});

let token = 0;
let ending: Promise<void> | undefined;

function endBatch() {
  if (!token) return;
  ending ??= api.EndCheckBatch(token).catch(error => {
    batch.error = errText(error);
  });
  return ending;
}

export function cancelBatch() {
  if (!batch.running || batch.stopping || batch.done === batch.total) return;
  batch.stopping = true;
  void endBatch();
}

export async function checkAll(ids: string[]) {
  if (batch.running || !ids.length) return;
  batch.running = true;
  batch.done = 0;
  batch.total = ids.length;
  batch.results = {};
  batch.cancelled = false;
  batch.error = '';
  try {
    token = await api.BeginCheckBatch();
    batch.states = Object.fromEntries(ids.map(id => [id, 'queued' as const]));
    let next = 0;
    async function worker() {
      while (!batch.stopping && next < ids.length) {
        const id = ids[next++];
        batch.states[id] = 'checking';
        try {
          const result = await api.CheckBatchProfile(token, id);
          if (batch.stopping) return;
          const failed = result.steps?.find(step => !step.ok && !step.skip);
          const detail = failed?.detail || failed?.name || 'соединение не прошло проверку';
          batch.results[id] = { ok: result.ok, label: result.ok
            ? 'Работает' + (result.responseMs != null ? ' · отклик ' + formatResponseMs(result.responseMs) : '')
            : 'Ошибка: ' + detail };
        } catch (error) {
          if (batch.stopping) return;
          batch.results[id] = { ok: false, label: 'Ошибка: ' + errText(error) };
        }
        delete batch.states[id];
        batch.done++;
      }
    }
    await Promise.all(Array.from({ length: Math.min(ids.length, 6) }, worker));
  } catch (error) {
    batch.error = errText(error);
  } finally {
    await endBatch();
    token = 0;
    ending = undefined;
    batch.cancelled = batch.stopping;
    batch.stopping = false;
    batch.states = {};
    batch.running = false;
  }
}
