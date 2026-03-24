import { create } from "zustand";
import type { CaptureStats, FlowSummary } from "../types";

const MAX_FLOWS = 500;

interface FlowState {
	flows: FlowSummary[];
	stats: CaptureStats;
	handleBatch: (
		newFlows: FlowSummary[],
		updatedFlows: FlowSummary[],
		stats: CaptureStats,
	) => void;
}

export const useFlowStore = create<FlowState>((set) => ({
	flows: [],
	stats: { packets_per_second: 0, active_flows: 0, total_devices: 0 },

	handleBatch: (newFlows, updatedFlows, stats) => {
		set((state) => {
			// Build lookup map for O(1) merge
			const flowMap = new Map<string, FlowSummary>();
			for (const f of state.flows) {
				flowMap.set(f.flow_key, f);
			}

			// Apply updates (overwrite existing)
			for (const f of updatedFlows) {
				flowMap.set(f.flow_key, f);
			}

			// Append new flows
			for (const f of newFlows) {
				flowMap.set(f.flow_key, f);
			}

			// Sort by last_seen desc, trim to MAX_FLOWS
			const sorted = Array.from(flowMap.values()).sort(
				(a, b) =>
					new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime(),
			);

			return {
				flows: sorted.slice(0, MAX_FLOWS),
				stats,
			};
		});
	},
}));
