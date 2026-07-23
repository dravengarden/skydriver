import { Box, useMediaQuery } from "@mui/material";

const beaconLanes = [
    { x: 118, delay: "-3s", duration: "23s", opacity: 0.34 },
    { x: 330, delay: "-11s", duration: "29s", opacity: 0.24 },
    { x: 610, delay: "-7s", duration: "26s", opacity: 0.3 },
    { x: 980, delay: "-15s", duration: "31s", opacity: 0.22 },
    { x: 1320, delay: "-5s", duration: "28s", opacity: 0.28 },
] as const;

const cloudBanks = [
    { y: 650, scale: 1.25, opacity: 0.34, duration: "72s", direction: 1 },
    { y: 770, scale: 1.7, opacity: 0.48, duration: "92s", direction: -1 },
    { y: 875, scale: 2.2, opacity: 0.68, duration: "112s", direction: 1 },
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
                stroke="rgba(255,255,255,0.42)"
                strokeWidth="2"
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
                bgcolor: "#102857",
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
                    <linearGradient id="skydriver-sky-field" x1="0" y1="0" x2="1" y2="1">
                        <stop stopColor="#102657" />
                        <stop offset="0.4" stopColor="#194d83" />
                        <stop offset="0.72" stopColor="#2588aa" />
                        <stop offset="1" stopColor="#6ab8c8" />
                    </linearGradient>
                    <radialGradient
                        id="skydriver-dawn"
                        cx="1320"
                        cy="60"
                        r="760"
                        gradientUnits="userSpaceOnUse"
                    >
                        <stop stopColor="#d8eef0" stopOpacity="0.34" />
                        <stop offset="0.24" stopColor="#a9d7dd" stopOpacity="0.2" />
                        <stop offset="0.64" stopColor="#6eb5c7" stopOpacity="0.06" />
                        <stop offset="1" stopColor="#6eb5c7" stopOpacity="0" />
                    </radialGradient>
                    <radialGradient id="skydriver-vignette" cx="50%" cy="48%" r="76%">
                        <stop offset="0.42" stopColor="#07152d" stopOpacity="0" />
                        <stop offset="1" stopColor="#07152d" stopOpacity="0.34" />
                    </radialGradient>
                    <linearGradient id="skydriver-lane" x1="0" y1="1" x2="0" y2="0">
                        <stop stopColor="#bff8ff" stopOpacity="0" />
                        <stop offset="0.25" stopColor="#c7f9ff" stopOpacity="0.62" />
                        <stop offset="1" stopColor="#ffffff" stopOpacity="0.16" />
                    </linearGradient>
                    <linearGradient id="skydriver-cloud-bank" x1="0" y1="0" x2="0" y2="1">
                        <stop stopColor="#e8f7f8" />
                        <stop offset="0.52" stopColor="#c7e8ec" />
                        <stop offset="1" stopColor="#70adbc" />
                    </linearGradient>
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

                <g fill="none" stroke="rgba(215,244,248,0.2)" strokeLinecap="round">
                    <path d="M-80 520C250 300 520 315 795 470s528 132 920-132" strokeWidth="1.6" />
                    <path d="M-65 585C275 390 525 405 808 535s536 106 860-75" strokeWidth="1" />
                </g>

                {beaconLanes.map((beacon) => (
                    <DataBeacon key={beacon.x} {...beacon} reducedMotion={reducedMotion} />
                ))}

                <g transform="translate(890 300)" opacity="0.34">
                    <path
                        d="M0 41c5-26 26-44 52-44 7 0 14 1 20 4 14-26 41-43 72-43 43 0 78 32 82 74 27 3 48 26 48 54H22C10 76 2 60 0 41Z"
                        fill="rgba(221,244,247,0.12)"
                        stroke="rgba(222,247,249,0.38)"
                        strokeWidth="2"
                    />
                    <path d="M135 70V1m0 0-17 22m17-22 17 22" stroke="#e5f7f8" strokeWidth="3" />
                    <path
                        d="M92 72h86M105 84h60M118 96h34"
                        stroke="#d5eef1"
                        strokeWidth="3"
                        strokeLinecap="round"
                    />
                </g>

                {cloudBanks.map((cloud) => (
                    <CloudBank key={cloud.y} {...cloud} reducedMotion={reducedMotion} />
                ))}

                <rect width="1600" height="900" fill="url(#skydriver-vignette)" />
                <rect width="1600" height="900" filter="url(#skydriver-grain)" opacity="0.42" />
            </svg>
        </Box>
    );
}
