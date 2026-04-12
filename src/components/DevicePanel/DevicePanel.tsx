import { ChevronRight, Monitor } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { getDevices } from "../../lib/tauri";
import type { Device } from "../../types";
import { DeviceRow } from "./DeviceRow";

interface DevicePanelProps {
	collapsed: boolean;
	onToggle: () => void;
}

export function DevicePanel({ collapsed, onToggle }: DevicePanelProps) {
	const [devices, setDevices] = useState<Device[]>([]);

	const fetchDevices = useCallback(async () => {
		const result = await getDevices();
		setDevices(
			result.sort(
				(a, b) =>
					new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime(),
			),
		);
	}, []);

	useEffect(() => {
		fetchDevices();
		const id = setInterval(fetchDevices, 5000);
		return () => clearInterval(id);
	}, [fetchDevices]);

	if (collapsed) {
		return (
			<button
				onClick={onToggle}
				className="flex h-full w-10 flex-col items-center justify-center border-l border-neutral-800 bg-neutral-900/50 text-neutral-500 transition-colors hover:text-neutral-300"
			>
				<ChevronRight className="h-4 w-4 rotate-180" />
				<Monitor className="mt-2 h-4 w-4" />
				<span className="mt-1 text-xs">{devices.length}</span>
			</button>
		);
	}

	return (
		<div className="flex h-full w-72 flex-col border-l border-neutral-800 bg-neutral-900/30">
			{/* Header */}
			<div className="flex items-center justify-between border-b border-neutral-800 px-3 py-2.5">
				<div className="flex items-center gap-2">
					<Monitor className="h-4 w-4 text-neutral-500" />
					<span className="text-sm font-medium text-neutral-300">Devices</span>
					<span className="rounded-full bg-neutral-800 px-1.5 py-0.5 font-mono text-xs text-neutral-500">
						{devices.length}
					</span>
				</div>
				<button
					onClick={onToggle}
					className="text-neutral-600 transition-colors hover:text-neutral-400"
				>
					<ChevronRight className="h-4 w-4" />
				</button>
			</div>

			{/* Device list */}
			<div className="flex-1 overflow-y-auto">
				{devices.map((device) => (
					<DeviceRow
						key={device.mac_address}
						device={device}
						onUpdate={fetchDevices}
					/>
				))}

				{devices.length === 0 && (
					<div className="px-4 py-8 text-center text-sm text-neutral-600">
						No devices discovered yet
					</div>
				)}
			</div>
		</div>
	);
}
