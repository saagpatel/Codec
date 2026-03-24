import { formatBytes, formatTimestamp } from "../../lib/formatters";
import type { FlowSummary } from "../../types";
import { ProtocolBadge } from "../shared/ProtocolBadge";

export function MessageBubble({ flow }: { flow: FlowSummary }) {
	const totalBytes = flow.bytes_sent + flow.bytes_received;

	return (
		<div className="flex items-start gap-3 rounded-lg border-l-2 border-neutral-700 bg-neutral-900 py-2 pl-3 pr-4">
			<div className="flex-1">
				<span className="font-mono text-xs text-neutral-400">
					{flow.summary_text ||
						`${flow.protocol} ${flow.src_ip} → ${flow.dst_ip}`}
				</span>
			</div>
			<div className="flex shrink-0 items-center gap-2">
				<ProtocolBadge protocol={flow.protocol} />
				<span className="font-mono text-xs text-neutral-600">
					{formatBytes(totalBytes)}
				</span>
				<span className="font-mono text-xs text-neutral-600">
					{formatTimestamp(flow.last_seen)}
				</span>
			</div>
		</div>
	);
}
