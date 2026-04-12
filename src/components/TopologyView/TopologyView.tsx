import { Network } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { getTopology } from "../../lib/tauri";
import type { TopologyEdge, TopologyNode } from "../../types";
import { NodeTooltip } from "./NodeTooltip";
import { useForceGraph } from "./useForceGraph";

export function TopologyView() {
	const svgRef = useRef<SVGSVGElement>(null);
	const containerRef = useRef<HTMLDivElement>(null);
	const [nodes, setNodes] = useState<TopologyNode[]>([]);
	const [edges, setEdges] = useState<TopologyEdge[]>([]);
	const [showServices, setShowServices] = useState(true);
	const [tooltip, setTooltip] = useState<{
		node: TopologyNode | null;
		x: number;
		y: number;
	}>({ node: null, x: 0, y: 0 });
	const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

	// Measure container
	useEffect(() => {
		const el = containerRef.current;
		if (!el) return;
		const observer = new ResizeObserver((entries) => {
			const entry = entries[0];
			if (entry) {
				setDimensions({
					width: entry.contentRect.width,
					height: entry.contentRect.height,
				});
			}
		});
		observer.observe(el);
		return () => observer.disconnect();
	}, []);

	// Poll topology every 2s
	useEffect(() => {
		let active = true;
		const poll = async () => {
			const [n, e] = await getTopology(60);
			if (active) {
				setNodes(n);
				setEdges(e);
			}
		};
		poll();
		const id = setInterval(poll, 2000);
		return () => {
			active = false;
			clearInterval(id);
		};
	}, []);

	const handleNodeHover = useCallback(
		(node: TopologyNode | null, event: MouseEvent) => {
			setTooltip({
				node,
				x: event?.clientX ?? 0,
				y: event?.clientY ?? 0,
			});
		},
		[],
	);

	useForceGraph(svgRef, nodes, edges, {
		width: dimensions.width,
		height: dimensions.height,
		showServices,
		onNodeHover: handleNodeHover,
	});

	if (nodes.length === 0) {
		return (
			<div className="flex flex-1 flex-col items-center justify-center gap-4 text-neutral-500">
				<Network className="h-16 w-16 animate-pulse text-neutral-600" />
				<div className="text-center">
					<h2 className="text-lg font-light text-neutral-400">
						Building topology&hellip;
					</h2>
					<p className="mt-1 text-sm">Waiting for device and flow data</p>
				</div>
			</div>
		);
	}

	return (
		<div ref={containerRef} className="relative flex-1 overflow-hidden">
			{/* Controls */}
			<div className="absolute left-4 top-4 z-10 flex gap-2">
				<button
					onClick={() => setShowServices((s) => !s)}
					className={`rounded-md border px-3 py-1.5 text-xs font-medium transition-colors ${
						showServices
							? "border-cyan-400/30 bg-cyan-400/10 text-cyan-400"
							: "border-neutral-700 bg-neutral-800 text-neutral-400 hover:text-neutral-300"
					}`}
				>
					Services {showServices ? "ON" : "OFF"}
				</button>
			</div>

			{/* Legend */}
			<div className="absolute bottom-4 left-4 z-10 flex gap-4 rounded-md border border-neutral-800 bg-neutral-900/80 px-3 py-2 text-xs">
				<span className="flex items-center gap-1.5">
					<span className="h-2.5 w-2.5 rounded-full bg-cyan-400" />
					Device
				</span>
				<span className="flex items-center gap-1.5">
					<span className="h-2.5 w-2.5 rounded-full bg-pink-400" />
					Router
				</span>
				<span className="flex items-center gap-1.5">
					<span className="h-2.5 w-2.5 rounded-full bg-slate-400 opacity-50" />
					Service
				</span>
			</div>

			<svg
				ref={svgRef}
				width={dimensions.width}
				height={dimensions.height}
				className="bg-neutral-950"
			/>

			<NodeTooltip node={tooltip.node} x={tooltip.x} y={tooltip.y} />
		</div>
	);
}
