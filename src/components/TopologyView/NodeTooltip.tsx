import { formatBytes } from "../../lib/formatters";
import type { TopologyNode } from "../../types";

interface NodeTooltipProps {
	node: TopologyNode | null;
	x: number;
	y: number;
}

export function NodeTooltip({ node, x, y }: NodeTooltipProps) {
	if (!node) return null;

	return (
		<div
			className="pointer-events-none fixed z-50 min-w-[180px] rounded-lg border border-neutral-700 bg-neutral-900 px-3 py-2 shadow-xl"
			style={{ left: x + 12, top: y - 12 }}
		>
			<div className="text-sm font-medium text-neutral-200">{node.label}</div>
			<div className="mt-1 space-y-0.5 font-mono text-xs text-neutral-500">
				<div>
					<span className="text-neutral-400">Type:</span> {node.node_type}
				</div>
				<div>
					<span className="text-neutral-400">ID:</span>{" "}
					{node.id.replace(/^(dev|svc|ip):/, "")}
				</div>
				<div>
					<span className="text-neutral-400">Traffic:</span>{" "}
					{formatBytes(node.total_bytes)}
				</div>
			</div>
		</div>
	);
}
