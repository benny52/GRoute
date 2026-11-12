import type { Connections, Flow } from '../api';
import { observedExit, type ObservedExit } from './flowRoute';

export interface Direction {
  key: string;
  process: string;
  pid: number;
  source: string;
  rule: string;
  destination: string;
  exit: ObservedExit;
  up: number;
  down: number;
  hasDown: boolean;
  measured: boolean;
}

interface Counters {
  sent: number;
  recv: number;
  closed: boolean;
  time: number;
}

export interface DirectionSample {
  time: number;
  wall: number;
  counters: Map<string, Counters>;
}

// dst comes from netip.AddrPort (IPv6 with brackets). Omit the port when
// grouping several simultaneous requests to the same destination.
function destinationOf(flow: Flow): string {
  if (flow.domain) return flow.domain;
  if (!flow.dst || flow.dst === 'invalid AddrPort') return '';
  return flow.dst.replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
}

export function sampleDirections(connections: Connections, previous: DirectionSample | null, time: number, wall: number) {
  // A minimized window or suspended computer has no recent samples.
  if (previous && (time <= previous.time || time - previous.time > 5000)) previous = null;
  const next: DirectionSample = { time, wall, counters: new Map() };
  const grouped = new Map<string, Direction>();

  for (const flow of [...connections.active, ...connections.closed]) {
    if (flow.stage === 'dns') continue; // DNS rows are aggregates, not flows.
    const id = `${flow.id}/${flow.start}`;
    if (next.counters.has(id)) continue;
    const old = previous?.counters.get(id);
    next.counters.set(id, { sent: flow.sent, recv: flow.recv, closed: flow.closed, time });
    // Include a short connection that both opened and closed between polls.
    // A historical closed row never contributes its lifetime total as a rate.
    const newInInterval = previous !== null && Date.parse(flow.start) >= previous.wall;
    if (flow.closed && (old?.closed || (!old && !newInInterval))) continue;
    const exit = observedExit(flow);
    const destination = destinationOf(flow);
    const source = flow.path || flow.process;
    const rule = flow.rule || (flow.excluded ? 'Системное исключение' : 'Правило не записано');
    const key = JSON.stringify([flow.pid, source, destination, rule, exit.kind, exit.serverId, exit.label]);
    let row = grouped.get(key);
    if (!row) {
      row = { key, process: flow.process, pid: flow.pid, source, rule, destination, exit, up: 0, down: 0, hasDown: true, measured: false };
      grouped.set(key, row);
    }
    if (flow.recv < 0) row.hasDown = false;
    if (!previous || (!old && !newInInterval)) continue;
    const seconds = (time - (old?.time ?? previous.time)) / 1000;
    row.up += Math.max(0, flow.sent - (old?.sent ?? 0)) / seconds;
    if (flow.recv >= 0) row.down += Math.max(0, flow.recv - Math.max(0, old?.recv ?? 0)) / seconds;
    row.measured = true;
  }

  // The controller reads its closed list before its active list. A flow
  // closing between those reads is absent once, then returns with final bytes.
  if (previous) {
    for (const [id, counters] of previous.counters) {
      if (!counters.closed && counters.time === previous.time && !next.counters.has(id)) {
        next.counters.set(id, counters);
      }
    }
  }

  const rows = [...grouped.values()].sort((a, b) => (b.up + b.down) - (a.up + a.down) || a.key.localeCompare(b.key));
  return { next, rows };
}
