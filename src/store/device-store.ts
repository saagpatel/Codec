import { create } from "zustand";
import type { Device } from "../types";

interface DeviceState {
	devices: Device[];
	handleBatch: (deviceUpdates: Device[]) => void;
	getDevice: (mac: string) => Device | undefined;
}

export const useDeviceStore = create<DeviceState>((set, get) => ({
	devices: [],

	handleBatch: (deviceUpdates) => {
		if (deviceUpdates.length === 0) return;

		set((state) => {
			const deviceMap = new Map<string, Device>();
			for (const d of state.devices) {
				deviceMap.set(d.mac_address, d);
			}

			for (const d of deviceUpdates) {
				const existing = deviceMap.get(d.mac_address);
				// Preserve user overrides from existing device
				if (existing) {
					d.id = existing.id;
					d.first_seen = existing.first_seen;
					if (existing.display_name && !d.display_name) {
						d.display_name = existing.display_name;
					}
					if (existing.icon !== "device" && d.icon === "device") {
						d.icon = existing.icon;
					}
				}
				d.last_seen = new Date().toISOString();
				deviceMap.set(d.mac_address, d);
			}

			return { devices: Array.from(deviceMap.values()) };
		});
	},

	getDevice: (mac) => {
		return get().devices.find((d) => d.mac_address === mac);
	},
}));
