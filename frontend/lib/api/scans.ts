// NetDigno — API functions for scans

import { apiClient } from './client';
import type {
  ScanOut,
  ScanProfile,
  PaginatedScans,
  ComparisonResult,
  Finding,
} from '../types/api';

export interface StartScanParams {
  target: string;
  profile: ScanProfile;
  authorized: boolean;
}

export interface ListScansParams {
  target?: string;
  profile?: string;
  status?: string;
  page?: number;
  page_size?: number;
}

export const startScan = (params: StartScanParams, timeoutMs?: number): Promise<ScanOut> =>
  apiClient.post<ScanOut>('/api/v1/scans', params, timeoutMs ?? 660_000);

export const listScans = (params: ListScansParams = {}): Promise<PaginatedScans> => {
  const qs = new URLSearchParams();
  if (params.target) qs.set('target', params.target);
  if (params.profile) qs.set('profile', params.profile);
  if (params.status) qs.set('status', params.status);
  if (params.page) qs.set('page', String(params.page));
  if (params.page_size) qs.set('page_size', String(params.page_size));
  const query = qs.toString();
  return apiClient.get<PaginatedScans>(`/api/v1/scans${query ? '?' + query : ''}`, 15_000);
};

export const getScan = (scanId: string): Promise<ScanOut> =>
  apiClient.get<ScanOut>(`/api/v1/scans/${scanId}`, 15_000);

export const getScanFindings = (scanId: string, state?: string): Promise<Finding[]> => {
  const query = state ? `?state=${encodeURIComponent(state)}` : '';
  return apiClient.get<Finding[]>(`/api/v1/scans/${scanId}/findings${query}`, 15_000);
};

export const compareScans = (
  baselineId: string,
  currentId: string
): Promise<ComparisonResult> =>
  apiClient.get<ComparisonResult>(
    `/api/v1/scans/compare?baseline_id=${encodeURIComponent(baselineId)}&current_id=${encodeURIComponent(currentId)}`,
    15_000
  );
