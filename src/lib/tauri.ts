import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
	CaptureStats,
	Device,
	DeviceStats,
	FlowSummary,
	IconKey,
	TopologyEdge,
	TopologyNode,
} from "../types";

// --- Wire format types (what Rust actually sends) ---

interface RawFlowEntry {
	flow_key: string;
	src_ip: string;
	dst_ip: string;
	src_port: number | null;
	dst_port: number | null;
	protocol: string;
	service_name: string | null;
	bytes_sent: number;
	bytes_received: number;
	packet_count: number;
	first_seen: number;
	last_seen: number;
	summary_text: string;
}

interface RawDeviceEntry {
	mac_address: string;
	ip_address: string | null;
	hostname: string | null;
	oui_manufacturer: string | null;
	device_type: string;
	display_name: string | null;
	icon: string;
	is_visible: boolean;
}

interface RawFlowBatch {
	timestamp: number;
	new_flows: RawFlowEntry[];
	updated_flows: RawFlowEntry[];
	device_updates: RawDeviceEntry[];
	stats: CaptureStats;
}

// --- Adapters ---

function msToIso(ms: number): string {
	return new Date(ms).toISOString();
}

function adaptFlow(raw: RawFlowEntry): FlowSummary {
	return {
		id: 0, // No ID from live stream, only from DB queries
		flow_key: raw.flow_key,
		src_ip: raw.src_ip,
		dst_ip: raw.dst_ip,
		src_port: raw.src_port,
		dst_port: raw.dst_port,
		protocol: raw.protocol as FlowSummary["protocol"],
		service_name: raw.service_name,
		src_device: null, // Resolved by store from deviceStore
		dst_device: null,
		bytes_sent: raw.bytes_sent,
		bytes_received: raw.bytes_received,
		packet_count: raw.packet_count,
		first_seen: msToIso(raw.first_seen),
		last_seen: msToIso(raw.last_seen),
		summary_text: raw.summary_text,
	};
}

function adaptDevice(raw: RawDeviceEntry): Device {
	return {
		id: 0,
		mac_address: raw.mac_address,
		ip_address: raw.ip_address,
		hostname: raw.hostname,
		oui_manufacturer: raw.oui_manufacturer,
		device_type: raw.device_type as Device["device_type"],
		display_name: raw.display_name,
		icon: (raw.icon || "device") as IconKey,
		is_visible: raw.is_visible,
		first_seen: new Date().toISOString(),
		last_seen: new Date().toISOString(),
	};
}

// --- Adapted batch for stores ---

export interface AdaptedBatch {
	newFlows: FlowSummary[];
	updatedFlows: FlowSummary[];
	deviceUpdates: Device[];
	stats: CaptureStats;
}

// --- Event subscription ---

export async function subscribeToFlowUpdates(
	onBatch: (batch: AdaptedBatch) => void,
): Promise<() => void> {
	const unlisten = await listen<RawFlowBatch>("flow-update", (event) => {
		const raw = event.payload;
		onBatch({
			newFlows: raw.new_flows.map(adaptFlow),
			updatedFlows: raw.updated_flows.map(adaptFlow),
			deviceUpdates: raw.device_updates.map(adaptDevice),
			stats: raw.stats,
		});
	});
	return unlisten;
}

// --- Tauri command wrappers ---

export async function getRecentFlows(limit: number): Promise<FlowSummary[]> {
	try {
		return await invoke<FlowSummary[]>("get_recent_flows", { limit });
	} catch (e) {
		console.error("get_recent_flows failed:", e);
		return [];
	}
}

export async function getDevices(): Promise<Device[]> {
	try {
		return await invoke<Device[]>("get_devices");
	} catch (e) {
		console.error("get_devices failed:", e);
		return [];
	}
}

export async function getSettings(): Promise<Record<string, string>> {
	try {
		return await invoke<Record<string, string>>("get_settings");
	} catch (e) {
		console.error("get_settings failed:", e);
		return {};
	}
}

export async function updateSetting(key: string, value: string): Promise<void> {
	try {
		await invoke("update_setting", { key, value });
	} catch (e) {
		console.error("update_setting failed:", e);
	}
}

export async function renameDevice(id: number, name: string): Promise<void> {
	try {
		await invoke("rename_device", { id, name });
	} catch (e) {
		console.error("rename_device failed:", e);
	}
}

export async function updateDeviceIcon(
	id: number,
	icon: IconKey,
): Promise<void> {
	try {
		await invoke("update_device_icon", { id, icon });
	} catch (e) {
		console.error("update_device_icon failed:", e);
	}
}

export async function toggleDeviceVisibility(
	id: number,
	visible: boolean,
): Promise<void> {
	try {
		await invoke("toggle_device_visibility", { id, visible });
	} catch (e) {
		console.error("toggle_device_visibility failed:", e);
	}
}

export async function getTopology(
	windowSecs?: number,
): Promise<[TopologyNode[], TopologyEdge[]]> {
	try {
		return await invoke<[TopologyNode[], TopologyEdge[]]>("get_topology", {
			windowSecs: windowSecs ?? 60,
		});
	} catch (e) {
		console.error("get_topology failed:", e);
		return [[], []];
	}
}

export async function getDeviceStats(
	deviceId: number,
): Promise<DeviceStats | null> {
	try {
		return await invoke<DeviceStats>("get_device_stats", { deviceId });
	} catch (e) {
		console.error("get_device_stats failed:", e);
		return null;
	}
}

export async function queryHistory(
	start: string,
	end: string,
	deviceId?: number,
	limit?: number,
): Promise<FlowSummary[]> {
	try {
		return await invoke<FlowSummary[]>("query_history", {
			start,
			end,
			deviceId: deviceId ?? null,
			limit: limit ?? 500,
		});
	} catch (e) {
		console.error("query_history failed:", e);
		return [];
	}
}
