import type { TunnelStatus } from '../api';

type Counters = Pick<TunnelStatus, 'id' | 'started' | 'sent' | 'recv'>;
type Speed = { up: number; down: number };
type Sample = Counters & { at: number; speed?: Speed };

export const maxSampleAge = 5000;

// Status events sometimes arrive between the regular one-second polls.
// Keep the baseline across short intervals so those events do not cause spikes.
export function createSpeedSampler() {
  let session: string | undefined;
  let previous = new Map<string, Sample>();
  return (since: string, tunnels: readonly Counters[], at: number) => {
    const next = new Map<string, Sample>();
    const servers = new Map<string, Speed>();
    const sum = { up: 0, down: 0 };
    for (const t of tunnels) {
      const old = since === session ? previous.get(t.id) : undefined;
      let sample: Sample = { id: t.id, started: t.started, sent: t.sent, recv: t.recv, at };
      if (old && old.started === t.started && old.sent >= 0 && old.recv >= 0 && t.sent >= old.sent && t.recv >= old.recv) {
        const ms = at - old.at;
        if (ms >= 0 && ms < 500) sample = old;
        else if (ms >= 500 && ms <= maxSampleAge) {
          sample.speed = { up: (t.sent - old.sent) * 1000 / ms, down: (t.recv - old.recv) * 1000 / ms };
        }
      }
      if (sample.speed) {
        servers.set(t.id, sample.speed);
        sum.up += sample.speed.up;
        sum.down += sample.speed.down;
      }
      next.set(t.id, sample);
    }
    previous = next;
    session = since;
    return { servers, total: servers.size === tunnels.length ? sum : undefined };
  };
}

const number = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 });
export function formatSpeed(bytes: number | undefined): string {
  if (bytes === undefined) return '—';
  if (bytes > 0 && bytes < 102.4) return '< 0,1 КБ/с';
  return bytes < 1024 ** 2
    ? number.format(bytes / 1024) + ' КБ/с'
    : number.format(bytes / 1024 ** 2) + ' МБ/с';
}
