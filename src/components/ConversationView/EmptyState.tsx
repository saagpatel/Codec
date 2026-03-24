import { Radio } from "lucide-react";

export function EmptyState() {
	return (
		<div className="flex flex-1 flex-col items-center justify-center gap-4 text-neutral-500">
			<Radio className="h-16 w-16 animate-pulse text-neutral-600" />
			<div className="text-center">
				<h2 className="text-lg font-light text-neutral-400">
					Listening for network traffic&hellip;
				</h2>
				<p className="mt-1 text-sm">Make sure the capture helper is running</p>
			</div>
		</div>
	);
}
