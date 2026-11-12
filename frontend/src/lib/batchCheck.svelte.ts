import { api, errText } from '../api';

export const batch = $state({
  running: false, done: 0, total: 0, current: '',
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
    for (const id of ids) {
      if (batch.stopping) break;
      batch.current = id;
      try {
        const result = await api.CheckBatchProfile(token, id);
        if (batch.stopping) break;
        const failed = result.steps?.find(step => !step.ok && !step.skip);
        const detail = failed?.detail || failed?.name || 'соединение не прошло проверку';
        batch.results[id] = { ok: result.ok, label: result.ok
          ? 'Работает' + (result.latencyMs ? ' · ' + result.latencyMs + ' мс' : '')
          : 'Ошибка: ' + detail };
      } catch (error) {
        if (batch.stopping) break;
        batch.results[id] = { ok: false, label: 'Ошибка: ' + errText(error) };
      }
      batch.done++;
    }
  } catch (error) {
    batch.error = errText(error);
  } finally {
    await endBatch();
    token = 0;
    ending = undefined;
    batch.cancelled = batch.stopping;
    batch.stopping = false;
    batch.current = '';
    batch.running = false;
  }
}
