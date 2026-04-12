import { Check, Eye, EyeOff, Pencil, X } from "lucide-react";
import { useState } from "react";
import { deviceDisplayName, formatTimestamp } from "../../lib/formatters";
import {
	renameDevice,
	toggleDeviceVisibility,
	updateDeviceIcon,
} from "../../lib/tauri";
import type { Device, IconKey } from "../../types";
import { DeviceIcon } from "../shared/DeviceIcon";

const ICON_OPTIONS: IconKey[] = [
	"phone",
	"laptop",
	"tv",
	"speaker",
	"camera",
	"router",
	"iot",
	"device",
];

interface DeviceRowProps {
	device: Device;
	onUpdate: () => void;
}

export function DeviceRow({ device, onUpdate }: DeviceRowProps) {
	const [editing, setEditing] = useState(false);
	const [editName, setEditName] = useState("");
	const [showIconPicker, setShowIconPicker] = useState(false);

	const displayName = deviceDisplayName(device, device.mac_address);

	const handleStartEdit = () => {
		setEditName(displayName);
		setEditing(true);
	};

	const handleSaveEdit = async () => {
		if (editName.trim()) {
			await renameDevice(device.id, editName.trim());
			onUpdate();
		}
		setEditing(false);
	};

	const handleCancelEdit = () => {
		setEditing(false);
	};

	const handleKeyDown = (e: React.KeyboardEvent) => {
		if (e.key === "Enter") handleSaveEdit();
		if (e.key === "Escape") handleCancelEdit();
	};

	const handleToggleVisibility = async () => {
		await toggleDeviceVisibility(device.id, !device.is_visible);
		onUpdate();
	};

	const handleIconChange = async (icon: IconKey) => {
		await updateDeviceIcon(device.id, icon);
		setShowIconPicker(false);
		onUpdate();
	};

	return (
		<div
			className={`group flex items-center gap-3 border-b border-neutral-800/50 px-3 py-2.5 ${
				!device.is_visible ? "opacity-40" : ""
			}`}
		>
			{/* Icon (click to change) */}
			<div className="relative">
				<button
					onClick={() => setShowIconPicker((s) => !s)}
					className="flex h-8 w-8 items-center justify-center rounded-md bg-neutral-800/50 text-neutral-400 transition-colors hover:bg-neutral-700/50"
				>
					<DeviceIcon icon={device.icon} className="h-4 w-4" />
				</button>

				{showIconPicker && (
					<div className="absolute left-0 top-full z-20 mt-1 grid grid-cols-4 gap-1 rounded-lg border border-neutral-700 bg-neutral-900 p-2 shadow-xl">
						{ICON_OPTIONS.map((icon) => (
							<button
								key={icon}
								onClick={() => handleIconChange(icon)}
								className={`flex h-7 w-7 items-center justify-center rounded ${
									device.icon === icon
										? "bg-cyan-400/20 text-cyan-400"
										: "text-neutral-400 hover:bg-neutral-800"
								}`}
							>
								<DeviceIcon icon={icon} className="h-3.5 w-3.5" />
							</button>
						))}
					</div>
				)}
			</div>

			{/* Name + details */}
			<div className="min-w-0 flex-1">
				{editing ? (
					<div className="flex items-center gap-1">
						<input
							type="text"
							value={editName}
							onChange={(e) => setEditName(e.target.value)}
							onKeyDown={handleKeyDown}
							autoFocus
							className="min-w-0 flex-1 rounded border border-neutral-600 bg-neutral-800 px-2 py-0.5 text-sm text-neutral-200 outline-none focus:border-cyan-400"
						/>
						<button
							onClick={handleSaveEdit}
							className="text-emerald-400 hover:text-emerald-300"
						>
							<Check className="h-3.5 w-3.5" />
						</button>
						<button
							onClick={handleCancelEdit}
							className="text-neutral-500 hover:text-neutral-300"
						>
							<X className="h-3.5 w-3.5" />
						</button>
					</div>
				) : (
					<div className="flex items-center gap-1.5">
						<span className="truncate text-sm text-neutral-200">
							{displayName}
						</span>
						<button
							onClick={handleStartEdit}
							className="text-neutral-600 opacity-0 transition-opacity group-hover:opacity-100 hover:text-neutral-400"
						>
							<Pencil className="h-3 w-3" />
						</button>
					</div>
				)}
				<div className="mt-0.5 flex items-center gap-2 font-mono text-xs text-neutral-600">
					<span>{device.ip_address ?? "—"}</span>
					<span>·</span>
					<span>{formatTimestamp(device.last_seen)}</span>
				</div>
			</div>

			{/* Visibility toggle */}
			<button
				onClick={handleToggleVisibility}
				className="text-neutral-600 transition-colors hover:text-neutral-400"
			>
				{device.is_visible ? (
					<Eye className="h-4 w-4" />
				) : (
					<EyeOff className="h-4 w-4" />
				)}
			</button>
		</div>
	);
}
