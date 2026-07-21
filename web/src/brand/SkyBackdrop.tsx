import { Box, useMediaQuery } from "@mui/material";

const beaconLanes = [
    { x: 118, delay: "-3s", duration: "17s", opacity: 0.72 },
    { x: 286, delay: "-11s", duration: "23s", opacity: 0.48 },
    { x: 512, delay: "-7s", duration: "19s", opacity: 0.62 },
    { x: 780, delay: "-15s", duration: "25s", opacity: 0.42 },
    { x: 1018, delay: "-5s", duration: "21s", opacity: 0.58 },
    { x: 1306, delay: "-13s", duration: "27s", opacity: 0.4 },
] as const;

const cloudBanks = [
    { y: 602, scale: 1.2, opacity: 0.76, duration: "58s", direction: 1 },
    { y: 708, scale: 1.55, opacity: 0.9, duration: "76s", direction: -1 },
    { y: 820, scale: 2.1, opacity: 0.98, duration: "94s", direction: 1 },
] as const;

function CloudBank({
    y,
    scale,
    opacity,
    duration,
    direction,
    reducedMotion,
}: (typeof cloudBanks)[number] & { readonly reducedMotion: boolean }) {
    const from = direction === 1 ? -120 : -20;
    const to = direction === 1 ? -20 : -120;

    return (
        <g opacity={opacity} transform={`translate(${from} ${y}) scale(${scale})`}>
            <path
                d="M0 88c35-37 75-48 120-32 21-43 63-65 111-51 27 8 47 27 58 52 50-17 97 1 126 42 45-22 101-16 139 20H0Z"
                fill="url(#skydriver-cloud-bank)"
            />
            <path
                d="M22 92c50-21 96-21 139 0 57-31 116-31 177 0 61-24 123-20 187 11"
                fill="none"
                stroke="rgba(255,255,255,0.76)"
                strokeWidth="3"
                strokeLinecap="round"
            />
            {reducedMotion ? null : (
                <animateTransform
                    attributeName="transform"
                    type="translate"
                    values={`${from} ${y};${to} ${y};${from} ${y}`}
                    dur={duration}
                    repeatCount="indefinite"
                />
            )}
        </g>
    );
}

function DataBeacon({
    x,
    delay,
    duration,
    opacity,
    reducedMotion,
}: (typeof beaconLanes)[number] & { readonly reducedMotion: boolean }) {
    return (
        <g opacity={opacity}>
            <path
                d={`M ${x} 760 C ${x - 54} 590 ${x + 84} 430 ${x + 18} 185`}
                fill="none"
                stroke="url(#skydriver-lane)"
                strokeWidth="2"
                strokeDasharray="5 15"
            />
            <circle cx={x} cy="760" r="5" fill="#d8fbff">
                {reducedMotion ? null : (
                    <animate
                        attributeName="cy"
                        values="760;185"
                        dur={duration}
                        begin={delay}
                        repeatCount="indefinite"
                    />
                )}
                {reducedMotion ? null : (
                    <animate
                        attributeName="opacity"
                        values="0;1;1;0"
                        keyTimes="0;0.08;0.86;1"
                        dur={duration}
                        begin={delay}
                        repeatCount="indefinite"
                    />
                )}
            </circle>
        </g>
    );
}

export function SkyBackdrop() {
    const reducedMotion = useMediaQuery("(prefers-reduced-motion: reduce)");

    return (
        <Box
            aria-hidden="true"
            sx={{
                position: "absolute",
                inset: 0,
                overflow: "hidden",
                bgcolor: "#142b70",
                pointerEvents: "none",
            }}
        >
            <svg
                viewBox="0 0 1600 900"
                preserveAspectRatio="xMidYMid slice"
                focusable="false"
                style={{ display: "block", width: "100%", height: "100%" }}
            >
                <defs>
                    <linearGradient id="skydriver-sky-field" x1="0" y1="0" x2="0.95" y2="1">
                        <stop stopColor="#172866" />
                        <stop offset="0.38" stopColor="#225db2" />
                        <stop offset="0.7" stopColor="#50b9df" />
                        <stop offset="1" stopColor="#c5eef5" />
                    </linearGradient>
                    <radialGradient
                        id="skydriver-dawn"
                        cx="1180"
                        cy="110"
                        r="680"
                        gradientUnits="userSpaceOnUse"
                    >
                        <stop stopColor="#fff8cf" stopOpacity="0.96" />
                        <stop offset="0.16" stopColor="#ffd67f" stopOpacity="0.44" />
                        <stop offset="0.52" stopColor="#bcecff" stopOpacity="0.1" />
                        <stop offset="1" stopColor="#82d6ef" stopOpacity="0" />
                    </radialGradient>
                    <linearGradient id="skydriver-lane" x1="0" y1="1" x2="0" y2="0">
                        <stop stopColor="#bff8ff" stopOpacity="0" />
                        <stop offset="0.25" stopColor="#c7f9ff" stopOpacity="0.62" />
                        <stop offset="1" stopColor="#ffffff" stopOpacity="0.16" />
                    </linearGradient>
                    <linearGradient id="skydriver-cloud-bank" x1="0" y1="0" x2="0" y2="1">
                        <stop stopColor="#ffffff" />
                        <stop offset="0.5" stopColor="#dff5fb" />
                        <stop offset="1" stopColor="#9dd8e9" />
                    </linearGradient>
                    <filter id="skydriver-haze" x="-30%" y="-40%" width="160%" height="180%">
                        <feGaussianBlur stdDeviation="18" />
                    </filter>
                    <filter id="skydriver-grain" x="0" y="0" width="100%" height="100%">
                        <feTurbulence
                            type="fractalNoise"
                            baseFrequency="0.68"
                            numOctaves="2"
                            seed="19"
                            result="noise"
                        />
                        <feColorMatrix in="noise" type="saturate" values="0" />
                        <feComponentTransfer>
                            <feFuncA type="table" tableValues="0 0.035" />
                        </feComponentTransfer>
                    </filter>
                </defs>

                <rect width="1600" height="900" fill="url(#skydriver-sky-field)" />
                <rect width="1600" height="900" fill="url(#skydriver-dawn)" />
                <circle cx="1180" cy="112" r="54" fill="#fff9d7" opacity="0.94" />
                <circle
                    cx="1180"
                    cy="112"
                    r="118"
                    fill="#ffe8a2"
                    opacity="0.2"
                    filter="url(#skydriver-haze)"
                />

                <g fill="none" stroke="rgba(220,249,255,0.34)" strokeLinecap="round">
                    <path d="M-80 520C250 300 520 315 795 470s528 132 920-132" strokeWidth="2.2" />
                    <path d="M-65 585C275 390 525 405 808 535s536 106 860-75" strokeWidth="1.3" />
                </g>

                {beaconLanes.map((beacon) => (
                    <DataBeacon key={beacon.x} {...beacon} reducedMotion={reducedMotion} />
                ))}

                <g transform="translate(850 292)" opacity="0.82">
                    <path
                        d="M0 41c5-26 26-44 52-44 7 0 14 1 20 4 14-26 41-43 72-43 43 0 78 32 82 74 27 3 48 26 48 54H22C10 76 2 60 0 41Z"
                        fill="rgba(241,252,255,0.28)"
                        stroke="rgba(238,253,255,0.5)"
                        strokeWidth="2"
                    />
                    <path d="M135 70V1m0 0-17 22m17-22 17 22" stroke="#effdff" strokeWidth="4" />
                    <path
                        d="M92 72h86M105 84h60M118 96h34"
                        stroke="#d5f8ff"
                        strokeWidth="4"
                        strokeLinecap="round"
                    />
                </g>

                {cloudBanks.map((cloud) => (
                    <CloudBank key={cloud.y} {...cloud} reducedMotion={reducedMotion} />
                ))}

                <rect width="1600" height="900" filter="url(#skydriver-grain)" opacity="0.65" />
            </svg>
        </Box>
    );
}
