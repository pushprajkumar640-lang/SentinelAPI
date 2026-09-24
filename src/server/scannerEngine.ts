import { ScanResult } from '../types/security';
import { orchestrateScan, ScanExecutionOptions } from './scanner/scanOrchestrator';

export type ScanOptions = ScanExecutionOptions;

export async function runSecurityScan(options: ScanOptions): Promise<ScanResult> {
  return orchestrateScan(options);
}
