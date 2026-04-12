import { Clock, MessageSquare, Network } from "lucide-react";
import { useEffect, useState } from "react";
import { ConversationView } from "./components/ConversationView/ConversationView";
import { DevicePanel } from "./components/DevicePanel/DevicePanel";
import { HistoryPanel } from "./components/HistoryPanel/HistoryPanel";
import { StatusBar } from "./components/shared/StatusBar";
import { TopologyView } from "./components/TopologyView/TopologyView";
import { subscribeToFlowUpdates } from "./lib/tauri";
import { useDeviceStore } from "./store/device-store";
import { useFlowStore } from "./store/flow-store";
import type { ViewTab } from "./types";

const TABS: { id: ViewTab; label: string; Icon: typeof MessageSquare }[] = [
	{ id: "conversations", label: "Conversations", Icon: MessageSquare },
	{ id: "topology", label: "Topology", Icon: Network },
	{ id: "history", label: "History", Icon: Clock },
];

function App() {
	const handleFlowBatch = useFlowStore((s) => s.handleBatch);
	const handleDeviceBatch = useDeviceStore((s) => s.handleBatch);
	const [activeTab, setActiveTab] = useState<ViewTab>("conversations");
	const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

	useEffect(() => {
		const unsubscribe = subscribeToFlowUpdates((batch) => {
			handleFlowBatch(batch.newFlows, batch.updatedFlows, batch.stats);
			handleDeviceBatch(batch.deviceUpdates);
		});

		return () => {
			unsubscribe.then((fn) => fn());
		};
	}, [handleFlowBatch, handleDeviceBatch]);

	return (
		<div className="flex h-screen flex-col bg-neutral-950">
			{/* Tab bar */}
			<nav className="flex items-center border-b border-neutral-800 bg-neutral-900/50">
				{TABS.map(({ id, label, Icon }) => (
					<button
						key={id}
						onClick={() => setActiveTab(id)}
						className={`flex items-center gap-2 px-5 py-2.5 text-sm font-medium transition-colors ${
							activeTab === id
								? "border-b-2 border-cyan-400 text-cyan-400"
								: "text-neutral-500 hover:text-neutral-300"
						}`}
					>
						<Icon className="h-4 w-4" />
						{label}
					</button>
				))}
			</nav>

			{/* Main content area */}
			<div className="flex min-h-0 flex-1">
				{/* View */}
				<div className="flex min-w-0 flex-1 flex-col">
					{activeTab === "conversations" && <ConversationView />}
					{activeTab === "topology" && <TopologyView />}
					{activeTab === "history" && <HistoryPanel />}
				</div>

				{/* Device sidebar */}
				<DevicePanel
					collapsed={sidebarCollapsed}
					onToggle={() => setSidebarCollapsed((s) => !s)}
				/>
			</div>

			<StatusBar />
		</div>
	);
}

export default App;
