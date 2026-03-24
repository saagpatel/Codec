import { useFlowStore } from "../../store/flow-store";

export function StatusBar() {
	const stats = useFlowStore((s) => s.stats);
	const isCapturing = stats.packets_per_second > 0;

	return (
		<footer className="fixed inset-x-0 bottom-0 flex h-10 items-center gap-6 border-t border-neutral-800 bg-neutral-900 px-4 font-mono text-xs text-neutral-500">
			<span className="flex items-center gap-2">
				<span
					className={`h-2 w-2 rounded-full ${
						isCapturing ? "animate-pulse bg-emerald-400" : "bg-red-400"
					}`}
				/>
				{isCapturing ? "Capturing" : "Stopped"}
			</span>
			<span>{stats.packets_per_second.toFixed(0)} pkt/s</span>
			<span>{stats.active_flows} flows</span>
			<span>{stats.total_devices} devices</span>
		</footer>
	);
}
