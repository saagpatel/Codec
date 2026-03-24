import { ChevronDown } from "lucide-react";
import { useState } from "react";
import {
	deviceDisplayName,
	formatBytes,
	formatTimestamp,
} from "../../lib/formatters";
import type { Device, FlowSummary } from "../../types";
import { DeviceIcon } from "../shared/DeviceIcon";
import { ProtocolBadge } from "../shared/ProtocolBadge";
import { MessageBubble } from "./MessageBubble";

interface ConversationThreadProps {
	deviceIp: string;
	service: string;
	flows: FlowSummary[];
	device: Device | null;
}

export function ConversationThread({
	deviceIp,
	service,
	flows,
	device,
}: ConversationThreadProps) {
	const [expanded, setExpanded] = useState(false);

	const latestFlow = flows[0];
	const totalBytes = flows.reduce(
		(sum, f) => sum + f.bytes_sent + f.bytes_received,
		0,
	);

	return (
		<div className="border-b border-neutral-800/50">
			<button
				onClick={() => setExpanded(!expanded)}
				className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors duration-150 hover:bg-neutral-900/50"
			>
				{/* Device icon */}
				<div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-neutral-800/50 text-neutral-400">
					<DeviceIcon icon={device?.icon ?? "device"} />
				</div>

				{/* Content */}
				<div className="min-w-0 flex-1">
					<div className="flex items-center gap-2">
						<span className="truncate font-medium text-neutral-200">
							{deviceDisplayName(device, deviceIp)}
						</span>
						<span className="text-neutral-600">&rarr;</span>
						<span className="truncate font-mono text-sm text-neutral-400">
							{service}
						</span>
					</div>
					<div className="mt-0.5 truncate text-xs text-neutral-500">
						{latestFlow?.summary_text}
					</div>
				</div>

				{/* Right side */}
				<div className="flex shrink-0 items-center gap-3">
					<ProtocolBadge protocol={latestFlow?.protocol ?? "TCP"} />
					<span className="font-mono text-xs text-neutral-500">
						{formatBytes(totalBytes)}
					</span>
					<span className="font-mono text-xs text-neutral-600">
						{formatTimestamp(latestFlow?.last_seen ?? new Date().toISOString())}
					</span>
					<ChevronDown
						className={`h-4 w-4 text-neutral-600 transition-transform duration-200 ${
							expanded ? "rotate-180" : ""
						}`}
					/>
				</div>
			</button>

			{/* Expanded: last 5 flows */}
			{expanded && (
				<div className="space-y-1 px-4 pb-3 pl-[4.25rem]">
					{flows.slice(0, 5).map((flow) => (
						<MessageBubble key={flow.flow_key} flow={flow} />
					))}
				</div>
			)}
		</div>
	);
}
