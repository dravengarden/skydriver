import { useId, type SVGProps } from "react";

interface SkydriverMarkProps extends SVGProps<SVGSVGElement> {
    readonly title?: string;
}

export function SkydriverMark({ title, ...props }: SkydriverMarkProps) {
    const instance = useId().replaceAll(":", "");
    const skyGradient = `skydriver-sky-${instance}`;
    const laneGradient = `skydriver-lane-${instance}`;

    return (
        <svg
            viewBox="0 0 64 64"
            role={title === undefined ? undefined : "img"}
            aria-hidden={title === undefined ? true : undefined}
            focusable="false"
            {...props}
        >
            {title === undefined ? null : <title>{title}</title>}
            <defs>
                <linearGradient id={skyGradient} x1="8" y1="5" x2="55" y2="60">
                    <stop stopColor="#263d8f" />
                    <stop offset="0.52" stopColor="#276bd7" />
                    <stop offset="1" stopColor="#33b8eb" />
                </linearGradient>
                <linearGradient id={laneGradient} x1="32" y1="50" x2="32" y2="12">
                    <stop stopColor="#b8f2ff" />
                    <stop offset="1" stopColor="#ffffff" />
                </linearGradient>
            </defs>
            <rect x="2" y="2" width="60" height="60" rx="17" fill={`url(#${skyGradient})`} />
            <path
                d="M13 28.5c.5-5.2 4.7-9.2 9.9-9.2 1 0 2 .1 2.9.4C28.1 15.1 32.8 12 38.3 12c7.3 0 13.3 5.6 13.9 12.8 3.1 1 5.3 3.8 5.3 7.1 0 4.1-3.4 7.5-7.5 7.5H16.5A8.5 8.5 0 0 1 13 28.5Z"
                fill="rgba(255,255,255,0.24)"
            />
            <path
                d="M31.9 12.4 22.3 29h6v11.2h7.2V29h6Z"
                fill={`url(#${laneGradient})`}
                stroke="rgba(255,255,255,0.88)"
                strokeLinejoin="round"
                strokeWidth="1.2"
            />
            <g fill="none" stroke="#e9fbff" strokeLinecap="round">
                <path d="M14.5 43.5h35" strokeWidth="3.2" opacity="0.95" />
                <path d="M18 49.5h28" strokeWidth="3.2" opacity="0.8" />
                <path d="M23 55.5h18" strokeWidth="3.2" opacity="0.62" />
            </g>
            <g fill="#ffffff">
                <circle cx="14.5" cy="43.5" r="2.1" />
                <circle cx="49.5" cy="43.5" r="2.1" />
                <circle cx="18" cy="49.5" r="1.9" opacity="0.9" />
                <circle cx="46" cy="49.5" r="1.9" opacity="0.9" />
            </g>
        </svg>
    );
}
