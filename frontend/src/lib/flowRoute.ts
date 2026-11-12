import { isGroupId, type Flow } from '../api';

export interface ObservedExit {
  kind: 'direct' | 'block' | 'vpn' | 'unknown';
  serverId?: string;
  label?: string;
}

// A profile is also recorded for failed and still pending attempts. Only
// report a concrete exit after the relay or UDP forwarder actually used it.
export function observedExit(flow: Flow): ObservedExit {
  const { route, outcome, profile } = flow;
  if (flow.stage === 'dns') return { kind: 'unknown', label: 'DNS-запрос' };
  if (route === 'block' && (outcome.startsWith('dropped:') || outcome.startsWith('rst:'))) return { kind: 'block' };
  if (route === 'direct' && (outcome === 'passed' || outcome === 'relayed')) return { kind: 'direct' };
  if (route === 'tunnel' && (outcome === 'relayed' || (outcome === 'tunneled' && (flow.sent > 0 || flow.recv > 0)))) {
    // The Telegram bridge may choose its own upstream; the row does not identify it.
    if (profile === 'telegram-ws') return { kind: 'unknown', label: 'Мост Telegram · выход неизвестен' };
    if (profile && !isGroupId(profile)) return { kind: 'vpn', serverId: profile };
    return { kind: 'vpn', label: 'Сервер неизвестен' };
  }
  if (outcome.startsWith('rst:') || outcome.startsWith('dropped:') || outcome.startsWith('aborted')) {
    return { kind: 'unknown', label: 'Соединение не установлено' };
  }
  return { kind: 'unknown', label: 'Выход пока неизвестен' };
}
