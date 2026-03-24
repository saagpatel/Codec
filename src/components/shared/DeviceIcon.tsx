import {
	Camera,
	Cpu,
	HardDrive,
	Laptop,
	Router,
	Smartphone,
	Speaker,
	Tv,
} from "lucide-react";
import type { IconKey } from "../../types";

const ICON_MAP: Record<IconKey, React.ComponentType<{ className?: string }>> = {
	phone: Smartphone,
	laptop: Laptop,
	tv: Tv,
	speaker: Speaker,
	camera: Camera,
	router: Router,
	iot: Cpu,
	device: HardDrive,
};

export function DeviceIcon({
	icon,
	className = "h-5 w-5",
}: {
	icon: IconKey;
	className?: string;
}) {
	const Icon = ICON_MAP[icon] ?? HardDrive;
	return <Icon className={className} />;
}
