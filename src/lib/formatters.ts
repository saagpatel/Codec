import type { Device, FlowSummary } from "../types";

export function formatBytes(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
	if (bytes < 1024 * 1024 * 1024)
		return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
	return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

export function formatTimestamp(iso: string): string {
	const ms = Date.now() - new Date(iso).getTime();
	if (ms < 5000) return "now";
	if (ms < 60_000) return `${Math.floor(ms / 1000)}s ago`;
	if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
	if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
	return `${Math.floor(ms / 86_400_000)}d ago`;
}

export function deviceDisplayName(
	device: Device | null,
	fallbackIp: string,
): string {
	if (!device) return fallbackIp;
	return (
		device.display_name ??
		device.hostname ??
		device.oui_manufacturer ??
		device.ip_address ??
		fallbackIp
	);
}

export function threadGroupKey(flow: FlowSummary): string {
	const deviceId = flow.src_device?.mac_address ?? flow.src_ip;
	const serviceId = flow.service_name ?? flow.dst_ip;
	return `${deviceId}::${serviceId}`;
}
