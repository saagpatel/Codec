import { Clock, Search, X } from "lucide-react";
import { useCallback, useState } from "react";
import { formatBytes, formatTimestamp } from "../../lib/formatters";
import { queryHistory } from "../../lib/tauri";
import { useDeviceStore } from "../../store/device-store";
import type { FlowSummary } from "../../types";
import { ProtocolBadge } from "../shared/ProtocolBadge";

type TimePreset = "1h" | "6h" | "24h" | "7d";

const PRESETS: { label: string; value: TimePreset }[] = [
	{ label: "1h", value: "1h" },
	{ label: "6h", value: "6h" },
	{ label: "24h", value: "24h" },
	{ label: "7d", value: "7d" },
];

function presetToRange(preset: TimePreset): { start: string; end: string } {
	const now = new Date();
	const end = now.toISOString();
	const ms: Record<TimePreset, number> = {
		"1h": 3_600_000,
		"6h": 21_600_000,
		"24h": 86_400_000,
		"7d": 604_800_000,
	};
	const start = new Date(now.getTime() - ms[preset]).toISOString();
	return { start, end };
}

export function HistoryPanel() {
	const devices = useDeviceStore((s) => s.devices);
	const [preset, setPreset] = useState<TimePreset>("24h");
	const [deviceFilter, setDeviceFilter] = useState<number | undefined>();
	const [results, setResults] = useState<FlowSummary[]>([]);
	const [loading, setLoading] = useState(false);
	const [hasQueried, setHasQueried] = useState(false);

	const handleQuery = useCallback(async () => {
		setLoading(true);
		const { start, end } = presetToRange(preset);
		const flows = await queryHistory(start, end, deviceFilter, 500);
		setResults(flows);
		setLoading(false);
		setHasQueried(true);
	}, [preset, deviceFilter]);

	const handleClear = () => {
		setResults([]);
		setHasQueried(false);
		setDeviceFilter(undefined);
		setPreset("24h");
	};

	return (
		<div className="flex flex-1 flex-col overflow-hidden">
			{/* Filters bar */}
			<div className="flex items-center gap-3 border-b border-neutral-800 px-4 py-3">
				{/* Time presets */}
				<div className="flex rounded-md border border-neutral-700">
					{PRESETS.map((p) => (
						<button
							key={p.value}
							onClick={() => setPreset(p.value)}
							className={`px-3 py-1 text-xs font-medium transition-colors ${
								preset === p.value
									? "bg-cyan-400/10 text-cyan-400"
									: "text-neutral-500 hover:text-neutral-300"
							}`}
						>
							{p.label}
						</button>
					))}
				</div>

				{/* Device filter */}
				<select
					value={deviceFilter ?? ""}
					onChange={(e) =>
						setDeviceFilter(e.target.value ? Number(e.target.value) : undefined)
					}
					className="rounded-md border border-neutral-700 bg-neutral-800 px-2 py-1 text-xs text-neutral-300 outline-none focus:border-cyan-400"
				>
					<option value="">All devices</option>
					{devices.map((d) => (
						<option key={d.mac_address} value={d.id}>
							{d.display_name ?? d.hostname ?? d.ip_address ?? d.mac_address}
						</option>
					))}
				</select>

				{/* Query button */}
				<button
					onClick={handleQuery}
					disabled={loading}
					className="flex items-center gap-1.5 rounded-md bg-cyan-400/10 px-3 py-1 text-xs font-medium text-cyan-400 transition-colors hover:bg-cyan-400/20 disabled:opacity-50"
				>
					<Search className="h-3 w-3" />
					{loading ? "Querying…" : "Query"}
				</button>

				{hasQueried && (
					<button
						onClick={handleClear}
						className="flex items-center gap-1 text-xs text-neutral-500 hover:text-neutral-300"
					>
						<X className="h-3 w-3" />
						Clear
					</button>
				)}

				{hasQueried && (
					<span className="ml-auto font-mono text-xs text-neutral-600">
						{results.length} results
					</span>
				)}
			</div>

			{/* Results */}
			<div className="flex-1 overflow-y-auto">
				{!hasQueried && (
					<div className="flex flex-1 flex-col items-center justify-center gap-4 py-20 text-neutral-500">
						<Clock className="h-12 w-12 text-neutral-600" />
						<div className="text-center">
							<h2 className="text-lg font-light text-neutral-400">
								Flow History
							</h2>
							<p className="mt-1 text-sm">
								Select a time range and click Query
							</p>
						</div>
					</div>
				)}

				{hasQueried && results.length === 0 && (
					<div className="py-12 text-center text-sm text-neutral-600">
						No flows found for this time range
					</div>
				)}

				{results.map((flow) => (
					<div
						key={flow.flow_key}
						className="flex items-center gap-3 border-b border-neutral-800/50 px-4 py-2"
					>
						<div className="min-w-0 flex-1">
							<div className="flex items-center gap-2">
								<span className="truncate text-sm text-neutral-300">
									{flow.src_ip}
								</span>
								<span className="text-neutral-600">→</span>
								<span className="truncate font-mono text-sm text-neutral-400">
									{flow.service_name ?? flow.dst_ip}
								</span>
							</div>
							{flow.summary_text && (
								<div className="mt-0.5 truncate text-xs text-neutral-600">
									{flow.summary_text}
								</div>
							)}
						</div>
						<ProtocolBadge protocol={flow.protocol} />
						<span className="shrink-0 font-mono text-xs text-neutral-500">
							{formatBytes(flow.bytes_sent + flow.bytes_received)}
						</span>
						<span className="shrink-0 font-mono text-xs text-neutral-600">
							{formatTimestamp(flow.last_seen)}
						</span>
					</div>
				))}
			</div>
		</div>
	);
}
