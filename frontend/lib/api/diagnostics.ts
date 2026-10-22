// NetScope — API functions for diagnostics

import { apiClient } from './client';
import type { DnsResult, TcpResult, RouteResult, HealthResponse } from '../types/api';

export const getHealth = (): Promise<HealthResponse> =>
  apiClient.get<HealthResponse>('/api/v1/health', 10_000);

export const checkDns = (hostname: string): Promise<DnsResult> =>
  apiClient.post<DnsResult>('/api/v1/diagnostics/dns', { hostname }, 15_000);

export const checkTcp = (
  target: string,
  port: number,
  timeout_seconds = 5
): Promise<TcpResult> =>
  apiClient.post<TcpResult>(
    '/api/v1/diagnostics/tcp',
    { target, port, timeout_seconds },
    30_000
  );

export const checkRoute = (target: string, max_hops = 20): Promise<RouteResult> =>
  apiClient.post<RouteResult>(
    '/api/v1/diagnostics/route',
    { target, max_hops },
    60_000
  );
