import { api } from '../api';
import { hide, mainText, targetText } from '../state.svelte';

export type Role = 'primary' | 'fallback' | 'both';
export interface AssignmentRow {
  rulesetId: string;
  ruleId: string;
  isDefault: boolean;
  index?: number;
  revision?: string;
}

export interface AssignmentRequest {
  operation: 'edit' | 'set' | 'replace' | 'transfer' | 'deleteSubscription' | 'deleteServer';
  edits?: { row: AssignmentRow; primary: string; fallback: string[]; beforePrimary: string; beforeFallback: string[] }[];
  role?: Role;
  rows?: AssignmentRow[];
  source?: string;
  target?: string;
  fallback?: string[];
  subscriptionId?: string;
}

export interface AssignmentUse {
  kind: 'rule' | 'default' | 'main' | 'group' | 'proxy' | 'server' | 'subscription';
  name: string;
  rulesetName?: string;
  rulesetId?: string;
  ruleKey?: string;
  role?: Role;
  position?: number;
  disabled?: boolean;
  indirect?: boolean;
  detail?: string;
}

export interface AssignmentChange extends AssignmentUse {
  before: string[];
  after: string[];
}

export interface AssignmentPreview {
  token: string;
  changes: AssignmentChange[];
  warnings?: string[];
  blockers?: string[];
}

export const assignments = api as typeof api & {
  PreviewAssignments(request: AssignmentRequest): Promise<AssignmentPreview>;
  ApplyAssignments(request: AssignmentRequest, token: string): Promise<void>;
  ServerAssignments(id: string): Promise<AssignmentUse[]>;
};

export function mainOption(): string {
  return 'Основной сервер — ' + (mainText() || 'не выбран на главной');
}

export function targetLabel(id: string): string {
  return id ? targetText(id) : 'Основной сервер';
}

export function useTitle(use: AssignmentUse): string {
  const kinds = { rule: '', default: '', group: 'Группа', proxy: 'Локальный прокси', main: '', server: 'Сервер', subscription: 'Подписка' };
  const name = use.kind === 'default' ? 'Всё остальное' : use.kind === 'main' && use.name === 'Основной сервер' ? 'Основной сервер на главной' : hide(use.name);
  return [hide(use.rulesetName), kinds[use.kind], name].filter(Boolean).join(' · ');
}

export function useRole(use: AssignmentUse): string {
  const role = use.role === 'primary' ? 'Приоритетный сервер' : use.role === 'fallback' ? 'Запасной сервер' : '';
  return [role + (use.position ? ' № ' + use.position : ''), use.disabled && 'выключено', use.indirect && 'косвенное использование'].filter(Boolean).join(' · ');
}
