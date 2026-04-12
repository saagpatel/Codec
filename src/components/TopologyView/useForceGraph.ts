import * as d3 from "d3";
import { useCallback, useEffect, useRef } from "react";
import type { TopologyEdge, TopologyNode } from "../../types";

const PROTOCOL_COLORS: Record<string, string> = {
	DNS: "#60a5fa", // blue-400
	TLS: "#34d399", // emerald-400
	HTTP: "#fbbf24", // amber-400
	mDNS: "#a78bfa", // violet-400
	DHCP: "#facc15", // yellow-400
	TCP: "#a3a3a3", // neutral-400
	UDP: "#a3a3a3",
};

const NODE_TYPE_COLORS: Record<string, string> = {
	device: "#22d3ee", // cyan-400
	router: "#f472b6", // pink-400
	service: "#94a3b8", // slate-400
};

interface UseForceGraphOptions {
	width: number;
	height: number;
	onNodeClick?: (nodeId: string) => void;
	onNodeHover?: (node: TopologyNode | null, event: MouseEvent) => void;
	showServices: boolean;
}

type SimNode = TopologyNode & d3.SimulationNodeDatum;
type SimLink = TopologyEdge & {
	source: SimNode | string;
	target: SimNode | string;
};

export function useForceGraph(
	svgRef: React.RefObject<SVGSVGElement | null>,
	nodes: TopologyNode[],
	edges: TopologyEdge[],
	options: UseForceGraphOptions,
) {
	const simulationRef = useRef<d3.Simulation<SimNode, SimLink> | null>(null);
	const zoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);

	const nodeRadius = useCallback((d: SimNode) => {
		return Math.max(8, Math.min(32, 4 + Math.log(d.total_bytes + 1) * 2));
	}, []);

	const linkWidth = useCallback((d: SimLink) => {
		return Math.max(1, Math.min(8, Math.log(d.bytes + 1) * 0.5));
	}, []);

	useEffect(() => {
		const svg = svgRef.current;
		if (!svg) return;

		const { width, height, showServices, onNodeClick, onNodeHover } = options;

		// Filter nodes based on showServices toggle
		const filteredNodes: SimNode[] = nodes
			.filter((n) => showServices || n.node_type !== "service")
			.map((n) => ({ ...n }));

		const nodeIds = new Set(filteredNodes.map((n) => n.id));
		const filteredEdges: SimLink[] = edges
			.filter((e) => {
				const src = typeof e.source === "string" ? e.source : e.source.id;
				const tgt = typeof e.target === "string" ? e.target : e.target.id;
				return nodeIds.has(src) && nodeIds.has(tgt);
			})
			.map((e) => ({ ...e }));

		const sel = d3.select(svg);
		sel.selectAll("*").remove();

		const g = sel.append("g").attr("class", "graph-container");

		// Zoom
		const zoom = d3
			.zoom<SVGSVGElement, unknown>()
			.scaleExtent([0.2, 4])
			.on("zoom", (event: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
				g.attr("transform", event.transform.toString());
			});
		sel.call(zoom);
		zoomRef.current = zoom;

		// Edge group
		const linkGroup = g.append("g").attr("class", "links");
		const linkSel = linkGroup
			.selectAll<SVGLineElement, SimLink>("line")
			.data(filteredEdges)
			.join("line")
			.attr("stroke", (d) => PROTOCOL_COLORS[d.protocol] ?? "#525252")
			.attr("stroke-width", linkWidth as (d: SimLink) => number)
			.attr("stroke-opacity", (d) => (d.active ? 0.8 : 0.3))
			.attr("stroke-dasharray", (d) => (d.active ? "6 3" : "none"));

		// Animate active edges
		linkSel
			.filter((d) => d.active)
			.each(function () {
				const el = d3.select(this);
				const animate = () => {
					el.attr("stroke-dashoffset", 0)
						.transition()
						.duration(1000)
						.ease(d3.easeLinear)
						.attr("stroke-dashoffset", -18)
						.on("end", animate);
				};
				animate();
			});

		// Node group
		const nodeGroup = g.append("g").attr("class", "nodes");
		const nodeSel = nodeGroup
			.selectAll<SVGGElement, SimNode>("g")
			.data(filteredNodes)
			.join("g")
			.attr("cursor", "pointer")
			.on("click", (_event, d) => onNodeClick?.(d.id))
			.on("mouseover", (event, d) => onNodeHover?.(d, event as MouseEvent))
			.on("mouseout", () => onNodeHover?.(null, null as unknown as MouseEvent));

		// Node circles
		nodeSel
			.append("circle")
			.attr("r", nodeRadius as (d: SimNode) => number)
			.attr(
				"fill",
				(d) => NODE_TYPE_COLORS[d.node_type] ?? NODE_TYPE_COLORS.device,
			)
			.attr("fill-opacity", (d) => (d.node_type === "service" ? 0.5 : 0.8))
			.attr("stroke", (d) => (d.node_type === "router" ? "#f472b6" : "#404040"))
			.attr("stroke-width", (d) => (d.node_type === "router" ? 2.5 : 1));

		// Node labels
		nodeSel
			.append("text")
			.text((d) => (d.label.length > 16 ? `${d.label.slice(0, 14)}…` : d.label))
			.attr("text-anchor", "middle")
			.attr("dy", (d) => nodeRadius(d) + 14)
			.attr("fill", "#a3a3a3")
			.attr("font-size", "11px")
			.attr("font-family", "Space Grotesk, sans-serif")
			.attr("pointer-events", "none");

		// Drag behavior
		const drag = d3
			.drag<SVGGElement, SimNode>()
			.on("start", (event, d) => {
				if (!event.active) simulationRef.current?.alphaTarget(0.3).restart();
				d.fx = d.x;
				d.fy = d.y;
			})
			.on("drag", (event, d) => {
				d.fx = event.x;
				d.fy = event.y;
			})
			.on("end", (event, d) => {
				if (!event.active) simulationRef.current?.alphaTarget(0);
				d.fx = null;
				d.fy = null;
			});
		nodeSel.call(drag);

		// Force simulation
		const simulation = d3
			.forceSimulation<SimNode>(filteredNodes)
			.force(
				"link",
				d3
					.forceLink<SimNode, SimLink>(filteredEdges)
					.id((d) => d.id)
					.distance(100),
			)
			.force("charge", d3.forceManyBody().strength(-200))
			.force("center", d3.forceCenter(width / 2, height / 2))
			.force(
				"collide",
				d3.forceCollide<SimNode>().radius((d) => nodeRadius(d) + 8),
			)
			.alphaDecay(0.02)
			.on("tick", () => {
				linkSel
					.attr("x1", (d) => (d.source as SimNode).x ?? 0)
					.attr("y1", (d) => (d.source as SimNode).y ?? 0)
					.attr("x2", (d) => (d.target as SimNode).x ?? 0)
					.attr("y2", (d) => (d.target as SimNode).y ?? 0);

				nodeSel.attr("transform", (d) => `translate(${d.x ?? 0},${d.y ?? 0})`);
			});

		simulationRef.current = simulation;

		return () => {
			simulation.stop();
		};
	}, [
		nodes,
		edges,
		options.width,
		options.height,
		options.showServices,
		nodeRadius,
		linkWidth,
		svgRef,
		options,
	]);
}
