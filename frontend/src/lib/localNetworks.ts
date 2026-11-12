import type { Rule } from '../api';

export const defaultNetworks = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

// Only adopt the exact rule produced by the earlier wizard. A user's
// similarly named rule with extra conditions must keep its own identity.
export function wizardNetworkRule(rule: Rule): boolean {
  if (rule.localNetworks) return true;
  return rule.name === 'Локальная сеть' && rule.action === 'direct' && !rule.apps?.length && !rule.app &&
    !rule.domain && !rule.ports && (!rule.protocol || rule.protocol === 'any') &&
    rule.domains?.length === 1 && rule.domains[0] === 'geoip:private';
}

export function readNetworks(input: string) {
  const cidrs: string[] = [];
  const ranges: { start: number; end: number; cidr: string }[] = [];
  const overlaps: string[] = [];
  let error = '';
  for (const cidr of input.trim().split(/[\s,;]+/).filter(Boolean)) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr);
    if (!m || m.slice(1).some((n) => n !== String(Number(n))) || m.slice(1, 5).some((n) => Number(n) > 255) || Number(m[5]) > 32) {
      error = `«${cidr}» — введите подсеть IPv4 в формате 10.20.0.0/16.`;
      break;
    }
    const address = m.slice(1, 5).reduce((n, octet) => n * 256 + Number(octet), 0);
    const size = 2 ** (32 - Number(m[5]));
    const start = Math.floor(address / size) * size;
    const end = start + size - 1;
    if (start !== address) {
      const network = [24, 16, 8, 0].map((shift) => (start >>> shift) & 255).join('.');
      error = `«${cidr}» содержит адрес устройства. Укажите адрес сети ${network}/${m[5]}.`;
      break;
    }
    if (cidrs.includes(cidr)) {
      error = `Подсеть ${cidr} указана дважды. Удалите повтор.`;
      break;
    }
    const overlap = ranges.find((r) => start <= r.end && r.start <= end);
    if (overlap) overlaps.push(`${cidr} и ${overlap.cidr}`);
    cidrs.push(cidr);
    ranges.push({ start, end, cidr });
  }
  return { cidrs, overlaps, error };
}
