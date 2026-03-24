import { useMemo, useState } from "react";
import { threadGroupKey } from "../../lib/formatters";
import { useDeviceStore } from "../../store/device-store";
import { useFlowStore } from "../../store/flow-store";
import type { Device, FlowSummary } from "../../types";
import { ConversationThread } from "./ConversationThread";
import { EmptyState } from "./EmptyState";

interface ThreadGroup {
	key: string;
	deviceIp: string;
	deviceMac: string | null;
	service: string;
	flows: FlowSummary[];
	device: Device | null;
	lastSeen: string;
}

const DEFAULT_VISIBLE = 10;

export function ConversationView() {
	const flows = useFlowStore((s) => s.flows);
	const devices = useDeviceStore((s) => s.devices);
	const [showAll, setShowAll] = useState(false);

	const threads = useMemo(() => {
		const deviceMap = new Map(devices.map((d) => [d.mac_address, d]));

		// Group flows by thread key
		const groups = new Map<string, ThreadGroup>();

		for (const flow of flows) {
			const key = threadGroupKey(flow);

			if (!groups.has(key)) {
				const deviceMac = flow.src_device?.mac_address ?? null;
				const device = deviceMac
					? (deviceMap.get(deviceMac) ?? flow.src_device)
					: null;

				// Skip hidden devices
				if (device && !device.is_visible) continue;

				groups.set(key, {
					key,
					deviceIp: flow.src_ip,
					deviceMac,
					service: flow.service_name ?? flow.dst_ip,
					flows: [],
					device,
					lastSeen: flow.last_seen,
				});
			}

			const group = groups.get(key);
			if (group) {
				group.flows.push(flow);
				if (flow.last_seen > group.lastSeen) {
					group.lastSeen = flow.last_seen;
				}
			}
		}

		// Sort by lastSeen desc
		return Array.from(groups.values()).sort(
			(a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime(),
		);
	}, [flows, devices]);

	if (threads.length === 0) {
		return <EmptyState />;
	}

	const visibleThreads = showAll ? threads : threads.slice(0, DEFAULT_VISIBLE);
	const hiddenCount = threads.length - DEFAULT_VISIBLE;

	return (
		<div className="flex-1 overflow-y-auto">
			{visibleThreads.map((thread) => (
				<ConversationThread
					key={thread.key}
					deviceIp={thread.deviceIp}
					service={thread.service}
					flows={thread.flows}
					device={thread.device}
				/>
			))}

			{!showAll && hiddenCount > 0 && (
				<button
					onClick={() => setShowAll(true)}
					className="w-full py-3 text-center text-sm text-neutral-500 transition-colors hover:text-neutral-300"
				>
					Show all ({hiddenCount} more)
				</button>
			)}
		</div>
	);
}
