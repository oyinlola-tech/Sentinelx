import {
  Activity,
  BarChart3,
  ClipboardList,
  Flame,
  FlaskConical,
  Gauge,
  Network,
  ScrollText,
  Settings,
  ShieldHalf,
  Siren,
} from "lucide-react";
import type { ReactNode } from "react";
import type { Role } from "@/lib/types";

export interface NavItem {
  href: string;
  label: string;
  icon: ReactNode;
  group: "Watch" | "Investigate" | "Respond" | "Administer";
  hint: string;
  badge?: "incidents" | "approvals";
  /** Lowest role that can use the page; lower roles do not see the link. */
  minRole: Role;
}

/** Every console page, in navigation order. The sidebar, command menu and footer read this. */
export const NAV: NavItem[] = [
  { href: "/", label: "Overview", icon: <Gauge />, group: "Watch", hint: "Sensor, risk and what needs a decision", minRole: "viewer" },
  { href: "/monitor", label: "Live monitor", icon: <Activity />, group: "Watch", hint: "Detections and responses as they happen", minRole: "viewer" },
  { href: "/threats", label: "Threats", icon: <Flame />, group: "Investigate", hint: "Sources ranked by risk", minRole: "viewer" },
  { href: "/incidents", label: "Incidents", icon: <Siren />, group: "Investigate", hint: "Correlated attacks", badge: "incidents", minRole: "viewer" },
  { href: "/network", label: "Network", icon: <Network />, group: "Investigate", hint: "Interfaces, traffic and top talkers", minRole: "viewer" },
  { href: "/analytics", label: "Analytics", icon: <BarChart3 />, group: "Investigate", hint: "Trends, categories and false positives", minRole: "viewer" },
  { href: "/firewall", label: "Firewall", icon: <ShieldHalf />, group: "Respond", hint: "Blocks, approvals and allowlist", badge: "approvals", minRole: "viewer" },
  { href: "/rules", label: "Rules", icon: <ScrollText />, group: "Respond", hint: "Custom detection rules", minRole: "viewer" },
  { href: "/lab", label: "PCAP Lab", icon: <FlaskConical />, group: "Respond", hint: "Replay captures through the engine", minRole: "viewer" },
  { href: "/audit", label: "Audit log", icon: <ClipboardList />, group: "Administer", hint: "Who did what, and when", minRole: "analyst" },
  { href: "/settings", label: "Settings", icon: <Settings />, group: "Administer", hint: "Detection, response and retention", minRole: "analyst" },
];
