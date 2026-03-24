import type { Protocol } from "../../types";

const PROTOCOL_STYLES: Record<Protocol, { bg: string; text: string }> = {
	DNS: { bg: "bg-blue-500/20", text: "text-blue-400" },
	TLS: { bg: "bg-emerald-500/20", text: "text-emerald-400" },
	HTTP: { bg: "bg-amber-500/20", text: "text-amber-400" },
	mDNS: { bg: "bg-violet-500/20", text: "text-violet-400" },
	DHCP: { bg: "bg-yellow-500/20", text: "text-yellow-400" },
	TCP: { bg: "bg-neutral-500/20", text: "text-neutral-400" },
	UDP: { bg: "bg-neutral-500/20", text: "text-neutral-400" },
};

export function ProtocolBadge({ protocol }: { protocol: Protocol }) {
	const style = PROTOCOL_STYLES[protocol] ?? PROTOCOL_STYLES.TCP;
	return (
		<span
			className={`${style.bg} ${style.text} inline-block rounded-full px-2 py-0.5 font-mono text-xs font-bold`}
		>
			{protocol}
		</span>
	);
}
