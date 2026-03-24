export type Protocol = "DNS" | "TLS" | "HTTP" | "mDNS" | "DHCP" | "TCP" | "UDP";
export type DeviceType =
	| "iPhone"
	| "Mac"
	| "SmartTV"
	| "IoT"
	| "Router"
	| "Unknown";
export type IconKey =
	| "phone"
	| "laptop"
	| "tv"
	| "speaker"
	| "camera"
	| "router"
	| "iot"
	| "device";

export interface Device {
	id: number;
	mac_address: string;
	ip_address: string | null;
	hostname: string | null;
	oui_manufacturer: string | null;
	device_type: DeviceType;
	display_name: string | null;
	icon: IconKey;
	is_visible: boolean;
	first_seen: string;
	last_seen: string;
}

export interface FlowSummary {
	id: number;
	flow_key: string;
	src_ip: string;
	dst_ip: string;
	src_port: number | null;
	dst_port: number | null;
	protocol: Protocol;
	service_name: string | null;
	src_device: Device | null;
	dst_device: Device | null;
	bytes_sent: number;
	bytes_received: number;
	packet_count: number;
	first_seen: string;
	last_seen: string;
	summary_text: string;
}

export interface CaptureStats {
	packets_per_second: number;
	active_flows: number;
	total_devices: number;
}

export interface FlowBatch {
	timestamp: string;
	new_flows: FlowSummary[];
	updated_flows: FlowSummary[];
	device_updates: Device[];
	stats: CaptureStats;
}

export interface TopologyNode {
	id: string;
	label: string;
	type: "device" | "service" | "router";
	device?: Device;
	x?: number;
	y?: number;
	fx?: number | null;
	fy?: number | null;
}

export interface TopologyEdge {
	source: string;
	target: string;
	protocol: Protocol;
	bytes: number;
	active: boolean;
}

export interface HistoryQuery {
	device_id?: number;
	start: string;
	end: string;
}
