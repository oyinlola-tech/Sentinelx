/**
 * Domain types for API responses.
 *
 * These mirror the canonical serialisers in the Python package
 * (packages/sentinelx/events/serialize.py and services/queries.py), which produce
 * the REST payloads, WebSocket payloads and CLI --json output alike. Request body
 * types come from the generated OpenAPI schema (api-schema.d.ts).
 */

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type RiskBand = "informational" | "low" | "medium" | "high" | "critical";
export type Role = "viewer" | "analyst" | "admin";
export type DetectionStatus = "new" | "acknowledged" | "false_positive" | "resolved";
export type IncidentStatus = "open" | "investigating" | "contained" | "resolved" | "false_positive";

export interface User {
  id: number;
  username: string;
  role: Role;
  is_active: boolean;
  must_change_password: boolean;
  last_login_at: string | null;
  created_at: string | null;
}

export interface Evidence {
  key: string;
  value: unknown;
  description: string;
  threshold: unknown;
  weight: number;
}

export interface Risk {
  score: number;
  band: RiskBand;
  contributions: Record<string, number>;
  rationale: string[];
  assessed_at?: string;
}

export interface ResponseAction {
  decision_id: string;
  decided_at: string;
  action: string;
  target: string;
  reason: string;
  outcome: "executed" | "simulated" | "skipped" | "failed" | "pending_approval";
  executed: boolean;
  dry_run: boolean;
  requires_approval: boolean;
  duration_seconds: number | null;
  detection_id: string | null;
  incident_id: string | null;
  error: string | null;
}

export interface Detection {
  detection_id: string;
  timestamp: string;
  detector: string;
  rule_name: string | null;
  category: string;
  severity: Severity;
  confidence: number;
  title: string;
  description: string;
  source_ip: string;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  evidence: Evidence[];
  recommended_action: string;
  risk: Risk;
  observation_window_seconds: number | null;
  packet_count: number | null;
  tags: string[];
  incident_id?: string | null;
  status?: DetectionStatus;
  reviewed_by?: string | null;
  replay_id?: string | null;
  actions?: ResponseAction[];
}

export interface TimelineEntry {
  timestamp: string;
  detection_id: string;
  detector: string;
  title: string;
  severity: Severity;
  risk: number;
  source_ip: string;
  destination_ip: string | null;
  destination_port: number | null;
}

export interface Incident {
  incident_id: string;
  title: string;
  summary: string;
  severity: Severity;
  status: IncidentStatus;
  risk: Risk;
  categories: string[];
  affected_sources: string[];
  affected_destinations: string[];
  affected_services: number[];
  correlation_rule: string | null;
  detection_count: number;
  timeline: TimelineEntry[];
  first_seen: string;
  last_seen: string;
  assigned_to?: string | null;
  notes?: string;
  replay_id?: string | null;
  detections?: Detection[];
  actions?: ResponseAction[];
  recommended_action?: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Threat {
  source_ip: string;
  detections: number;
  max_risk: number;
  severities: Record<string, number>;
  statuses: Record<string, number>;
  categories: string[];
  detectors: string[];
  destinations: string[];
  first_seen: string;
  last_seen: string;
  top_detection: Detection;
  incident_ids: string[];
  blocked: boolean;
  history: { detections: number; responses: number; last_score: number };
}

export interface BlockEntry {
  network: string;
  created_at: string;
  expires_at: string | null;
  temporary: boolean;
  remaining_seconds: number | null;
  comment: string;
  rate_limited: boolean;
}

export interface BlockHistory {
  id: number;
  network: string;
  created_at: string;
  expires_at: string | null;
  removed_at: string | null;
  active: boolean;
  rate_limited: boolean;
  reason: string;
  removal_reason: string | null;
  backend: string;
}

export interface PendingAction {
  action_id: string;
  action: string;
  target: string;
  reason: string;
  risk: number;
  duration_seconds: number | null;
  detection_id: string | null;
  incident_id: string | null;
  evidence: string[];
  created_at: string;
}

export interface ResponseStatus {
  mode: "detect_only" | "manual_approval" | "automatic";
  dry_run: boolean;
  prevention_active: boolean;
  firewall_backend: string;
  active_blocks: number;
  pending_approvals: number;
  safety_refusals: number;
  auto_block_threshold: number;
  allowlist: string[];
}

export interface FirewallOverview {
  status: ResponseStatus;
  health: { backend: string; ok: boolean; enforcing?: boolean; error?: string | null };
  active: BlockEntry[];
  history: BlockHistory[];
  actions: ResponseAction[];
  pending_approvals: PendingAction[];
}

export interface SensorStatus {
  sensor: string;
  state: "running" | "stopped" | "error";
  running: boolean;
  interface: string | null;
  bpf_filter: string | null;
  started_at: string | null;
  error: string | null;
  backend: string | null;
  capture: Record<string, number> | null;
  has_capture_privileges: boolean;
  safety: string;
}

export interface NetworkInterface {
  name: string;
  state: string;
  mac: string | null;
  mtu: number;
  is_up: boolean;
  is_loopback: boolean;
  addresses: string[];
  statistics: { rx_packets: number; tx_packets: number; rx_bytes: number; tx_bytes: number; rx_dropped: number };
}

export interface Overview {
  packets_processed: number;
  bytes_processed: number;
  packets_per_second: number | null;
  active_flows: number;
  tracked_sources: number;
  detections_24h: number;
  by_severity_24h: { key: string; count: number }[];
  open_incidents: number;
  critical_incidents: number;
  blocked_sources: number;
  pending_approvals: number;
  current_risk: number;
  top_incidents: Incident[];
  recent_detections: Detection[];
  protocols: Record<string, number>;
  sensor: SensorStatus;
  safety: string;
  health: "ok" | "degraded" | "error";
}

export interface Grouped { key: string | null; count: number }

export interface Analytics {
  since: string;
  hours: number;
  bucket_minutes: number;
  detections: number;
  by_severity: Grouped[];
  by_category: Grouped[];
  by_detector: Grouped[];
  top_sources: Grouped[];
  top_destinations: Grouped[];
  by_protocol: Grouped[];
  false_positives: number;
  reviewed: number;
  false_positive_rate: number | null;
  mean_risk: number | null;
  timeline: ({ bucket_start: string; total: number } & Partial<Record<Severity, number>>)[];
  detector_performance: { name: string; enabled: boolean; evaluations: number; hits: number; mean_eval_microseconds?: number }[];
  engine: Record<string, number>;
  system: { timestamp: string; cpu_percent: number; memory_bytes: number; packets_processed: number; packets_dropped: number }[];
}

export interface NetworkStats {
  state: Record<string, unknown> & { tracked_sources: number; active_flows: number; packets: number; bytes: number };
  top_sources: { source_ip: string; packets: number; bytes: number; unique_dst_ports: number; unique_dst_ips: number; packet_rate: number }[];
  top_destinations: { destination_ip: string; packets: number; bytes: number; flows: number }[];
  protocols: Record<string, number>;
  traffic: { bucket_start: string; packets: number; bytes: number; packets_per_second: number; detections: number }[];
  interfaces: NetworkInterface[];
}

export interface RuleSummary {
  rule_id: string;
  name: string;
  enabled: boolean;
  origin: "file" | "api";
  source_path: string | null;
  definition: string;
  updated_at: string;
  updated_by: string;
  valid: boolean;
  problems: string[];
  stats: { evaluations: number; hits: number; mean_eval_microseconds?: number } | null;
  description?: string;
  condition?: string;
  within_seconds?: number;
  severity?: Severity;
  category?: string;
  confidence?: number;
  action?: string;
  duration?: number | null;
  tags?: string[];
  tests?: { scenario: string; expect: string; params: Record<string, unknown> }[];
}

export interface RuleTestResult {
  target: string;
  matched?: boolean;
  detection_count?: number;
  packets?: number;
  sources?: Record<string, number>;
  elapsed_seconds?: number;
  first_detection?: string | null;
  evidence?: Evidence[];
  tests?: { scenario: string; expected: string; actual: string; detections: number; passed: boolean }[];
  passed?: boolean;
  count?: number;
}

export interface PcapFile { path: string; filename: string; size_bytes: number; modified_at: string }

export interface ReplayRun {
  replay_id: string;
  filename: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  created_by: string;
  options: { speed: number; limit: number | null };
  progress: Partial<{ frames: number; packets_per_second: number; detections: number; incidents: number; elapsed_seconds: number }>;
  error: string | null;
  report?: ReplayReport;
  summary?: Partial<ReplayReport> | null;
}

export interface ReplayReport {
  frames: number;
  packets_decoded: number;
  decode_failures: number;
  wall_seconds: number;
  capture_span_seconds: number;
  packets_per_second: number;
  detection_count: number;
  incident_count: number;
  detections_by_detector: Record<string, number>;
  detections_by_severity: Record<string, number>;
  response_decisions: Record<string, number>;
  latency: { per_packet_mean_ms: number; per_packet_p50_ms: number; per_packet_p99_ms: number; detection_mean_ms: number; detection_max_ms: number };
  resources: { cpu_percent_mean: number; cpu_percent_max: number; memory_peak_mb: number };
  detections: Detection[];
  incidents: Incident[];
  decisions: ResponseAction[];
  safety_note: string;
}

export interface AuditEvent {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  target: string | null;
  reason: string;
  source: string;
  outcome: string;
  client_ip: string | null;
  details: Record<string, unknown>;
}

export interface ConfigView {
  settings: Record<string, Record<string, unknown>>;
  editable: Record<string, string[]>;
  safety: { banner: string; prevention_active: boolean; confirmation_phrase: string; firewall_backend: string };
}

export type EventType =
  | "detection.created" | "incident.opened" | "incident.updated" | "incident.closed" | "severity.changed"
  | "ip.blocked" | "ip.unblocked" | "response.decided" | "response.pending_approval" | "sensor.status"
  | "packet.stats" | "system.health" | "replay.progress" | "replay.completed" | "audit.event"
  | "rule.changed" | "config.changed";

export interface StreamEvent<T = Record<string, unknown>> {
  id: string;
  type: EventType;
  timestamp: string;
  payload: T;
}

/* ------------------------------------------------------------------------------
 * Request bodies, generated from the API's OpenAPI document
 * (scripts/export_openapi.py -> npm run generate:api). Using these at call sites
 * makes a renamed or removed backend field a dashboard compile error.
 * --------------------------------------------------------------------------- */
import type { components } from "./api-schema";

type Schemas = components["schemas"];
export type BlockRequest = Schemas["BlockRequest"];
export type UnblockRequest = Schemas["UnblockRequest"];
export type RuleDefinitionRequest = Schemas["RuleDefinitionRequest"];
export type RuleTestRequest = Schemas["RuleTestRequest"];
export type ConfigUpdateRequest = Schemas["ConfigUpdateRequest"];
export type ReplayRequest = Schemas["ReplayRequest"];
export type LoginRequest = Schemas["LoginRequest"];
