import { useEffect } from "react";
import { ConversationView } from "./components/ConversationView/ConversationView";
import { StatusBar } from "./components/shared/StatusBar";
import { subscribeToFlowUpdates } from "./lib/tauri";
import { useDeviceStore } from "./store/device-store";
import { useFlowStore } from "./store/flow-store";

function App() {
	const handleFlowBatch = useFlowStore((s) => s.handleBatch);
	const handleDeviceBatch = useDeviceStore((s) => s.handleBatch);

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
			<ConversationView />
			<StatusBar />
		</div>
	);
}

export default App;
