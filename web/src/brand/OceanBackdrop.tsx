import { Box, useMediaQuery } from "@mui/material";

const VIEWBOX_WIDTH = 1600;
const VIEWBOX_HEIGHT = 900;
const WAVE_SAMPLES = 96;

interface WaveSpec {
    readonly id: string;
    readonly baseline: number;
    readonly amplitude: number;
    readonly primaryCycles: number;
    readonly secondaryCycles: number;
    readonly phase: number;
    readonly fill: string;
    readonly crest: string;
    readonly crestWidth: number;
    readonly opacity: number;
    readonly duration: string;
    readonly direction: "left" | "right";
}

const farWave = {
    id: "far",
    baseline: 410,
    amplitude: 13,
    primaryCycles: 3,
    secondaryCycles: 8,
    phase: 0.4,
    fill: "url(#carrack-ocean-far)",
    crest: "rgba(232, 252, 255, 0.52)",
    crestWidth: 2,
    opacity: 0.9,
    duration: "42s",
    direction: "right",
} satisfies WaveSpec;

const waves: readonly WaveSpec[] = [
    farWave,
    {
        id: "middle",
        baseline: 486,
        amplitude: 27,
        primaryCycles: 2,
        secondaryCycles: 7,
        phase: 1.9,
        fill: "url(#carrack-ocean-middle)",
        crest: "rgba(231, 253, 255, 0.62)",
        crestWidth: 2.5,
        opacity: 0.96,
        duration: "31s",
        direction: "left",
    },
    {
        id: "swell",
        baseline: 585,
        amplitude: 49,
        primaryCycles: 2,
        secondaryCycles: 5,
        phase: 0.8,
        fill: "url(#carrack-ocean-swell)",
        crest: "rgba(235, 254, 255, 0.7)",
        crestWidth: 3.2,
        opacity: 0.98,
        duration: "24s",
        direction: "right",
    },
    {
        id: "near",
        baseline: 704,
        amplitude: 76,
        primaryCycles: 2,
        secondaryCycles: 6,
        phase: 2.3,
        fill: "url(#carrack-ocean-near)",
        crest: "rgba(241, 255, 255, 0.78)",
        crestWidth: 4.2,
        opacity: 1,
        duration: "18s",
        direction: "left",
    },
    {
        id: "foreground",
        baseline: 825,
        amplitude: 58,
        primaryCycles: 3,
        secondaryCycles: 7,
        phase: 1.2,
        fill: "url(#carrack-ocean-foreground)",
        crest: "rgba(225, 251, 255, 0.62)",
        crestWidth: 4.8,
        opacity: 1,
        duration: "14s",
        direction: "right",
    },
];

function waveY(spec: WaveSpec, x: number): number {
    const normalized = x / VIEWBOX_WIDTH;
    const primary = Math.sin(Math.PI * 2 * spec.primaryCycles * normalized + spec.phase);
    const secondary = Math.sin(Math.PI * 2 * spec.secondaryCycles * normalized + spec.phase * 0.61);
    const chop = Math.sin(
        Math.PI * 2 * (spec.secondaryCycles + spec.primaryCycles) * normalized - spec.phase,
    );

    return spec.baseline + spec.amplitude * (primary * 0.7 + secondary * 0.22 + chop * 0.08);
}

function waveLine(spec: WaveSpec): string {
    const points = Array.from({ length: WAVE_SAMPLES + 1 }, (_, index) => {
        const x = (VIEWBOX_WIDTH * index) / WAVE_SAMPLES;
        return `${x.toFixed(1)} ${waveY(spec, x).toFixed(1)}`;
    });

    return `M ${points.join(" L ")}`;
}

function waveArea(spec: WaveSpec): string {
    return `${waveLine(spec)} L ${VIEWBOX_WIDTH} ${VIEWBOX_HEIGHT} L 0 ${VIEWBOX_HEIGHT} Z`;
}

function waveFoam(spec: WaveSpec): string {
    const top = Array.from({ length: WAVE_SAMPLES + 1 }, (_, index) => {
        const x = (VIEWBOX_WIDTH * index) / WAVE_SAMPLES;
        return `${x.toFixed(1)} ${waveY(spec, x).toFixed(1)}`;
    });
    const depth = Math.max(4, spec.crestWidth * 2.4);
    const bottom = Array.from({ length: WAVE_SAMPLES + 1 }, (_, index) => {
        const reversedIndex = WAVE_SAMPLES - index;
        const x = (VIEWBOX_WIDTH * reversedIndex) / WAVE_SAMPLES;
        const ripple = Math.sin(reversedIndex * 1.73 + spec.phase) * depth * 0.24;
        return `${x.toFixed(1)} ${(waveY(spec, x) + depth + ripple).toFixed(1)}`;
    });

    return `M ${top.join(" L ")} L ${bottom.join(" L ")} Z`;
}

const sunlightSparkles = Array.from({ length: 27 }, (_, index) => {
    const progress = index / 26;
    const y = 430 + progress * 390;
    const spread = 25 + progress * 185;
    const center = 285 + Math.sin(index * 2.17) * spread;
    const width = 18 + (index % 5) * 11 + progress * 28;

    return {
        x1: center - width / 2,
        x2: center + width / 2,
        y,
        opacity: 0.22 + (index % 4) * 0.05,
    };
});

const SHIP_ORIGIN_X = 1190;
const SHIP_CENTER_X = 88;
const SHIP_STERN_X = 18;
const SHIP_BOW_X = 160;
const SHIP_WATERLINE_Y = 100;
const SHIP_SCALE = 1.18;
const SHIP_POSE_SAMPLES = 48;

function wrapWaveX(x: number): number {
    return ((x % VIEWBOX_WIDTH) + VIEWBOX_WIDTH) % VIEWBOX_WIDTH;
}

function translatedWaveX(spec: WaveSpec, worldX: number, progress: number): number {
    const translation =
        spec.direction === "left"
            ? -VIEWBOX_WIDTH * progress
            : -VIEWBOX_WIDTH + VIEWBOX_WIDTH * progress;
    return wrapWaveX(worldX - translation);
}

function shipPose(progress: number): { readonly y: number; readonly pitch: number } {
    const sternWorldX = SHIP_ORIGIN_X + SHIP_CENTER_X + (SHIP_STERN_X - SHIP_CENTER_X) * SHIP_SCALE;
    const bowWorldX = SHIP_ORIGIN_X + SHIP_CENTER_X + (SHIP_BOW_X - SHIP_CENTER_X) * SHIP_SCALE;
    const sternY = waveY(farWave, translatedWaveX(farWave, sternWorldX, progress));
    const bowY = waveY(farWave, translatedWaveX(farWave, bowWorldX, progress));
    const waterlineY = (sternY + bowY) / 2;
    const surfacePitch =
        (Math.atan2(bowY - sternY, (SHIP_BOW_X - SHIP_STERN_X) * SHIP_SCALE) * 180) / Math.PI;

    return {
        y: waterlineY - SHIP_WATERLINE_Y,
        pitch: Math.max(-4.5, Math.min(4.5, surfacePitch)),
    };
}

// The ship samples the same translated wave at stern and bow. Their mean
// drives buoyant heave while their chord slope drives hull pitch.
const shipPoses = Array.from({ length: SHIP_POSE_SAMPLES + 1 }, (_, index) =>
    shipPose(index / SHIP_POSE_SAMPLES),
);
const shipKeyTimes = Array.from(
    { length: SHIP_POSE_SAMPLES + 1 },
    (_, index) => index / SHIP_POSE_SAMPLES,
).join(";");
const shipTranslationValues = shipPoses
    .map((pose) => `${SHIP_ORIGIN_X} ${pose.y.toFixed(2)}`)
    .join(";");
const shipPitchValues = shipPoses
    .map((pose) => `${pose.pitch.toFixed(2)} ${SHIP_CENTER_X} ${SHIP_WATERLINE_Y}`)
    .join(";");
const restingShipPose = shipPose(0);

function DistantCarrack({ reducedMotion }: { readonly reducedMotion: boolean }) {
    return (
        <g
            transform={
                reducedMotion
                    ? `translate(${SHIP_ORIGIN_X} ${restingShipPose.y.toFixed(2)})`
                    : undefined
            }
            opacity="0.78"
        >
            {reducedMotion ? null : (
                <animateTransform
                    attributeName="transform"
                    type="translate"
                    values={shipTranslationValues}
                    keyTimes={shipKeyTimes}
                    calcMode="linear"
                    dur={farWave.duration}
                    repeatCount="indefinite"
                />
            )}
            <g
                transform={
                    reducedMotion
                        ? `rotate(${restingShipPose.pitch.toFixed(2)} ${SHIP_CENTER_X} ${SHIP_WATERLINE_Y})`
                        : undefined
                }
            >
                <g
                    transform={`translate(${SHIP_CENTER_X} ${SHIP_WATERLINE_Y}) scale(${SHIP_SCALE}) translate(${-SHIP_CENTER_X} ${-SHIP_WATERLINE_Y})`}
                >
                    <path
                        d="M-55 99c21-7 42-7 64 0M-38 105c16-5 31-5 47 0"
                        fill="none"
                        stroke="#e8fbff"
                        strokeWidth="2"
                        strokeLinecap="round"
                        opacity="0.48"
                    />
                    <path
                        d="M47 18 94-2l51 26M47 19 14 79M145 24l24 50M94-1 7 79m87-80 76 74"
                        fill="none"
                        stroke="#795039"
                        strokeWidth="1.25"
                        opacity="0.64"
                    />
                    <path
                        d="M63 13Q94 4 125 13l-5 32q-26 10-52 1Z"
                        fill="url(#carrack-canvas-sail)"
                    />
                    <path d="M69 51q25-7 48 0l-3 19q-20 8-41 1Z" fill="#f2ddb3" />
                    <path d="M20 30q27-8 50 0l-3 27q-21 8-43 0Z" fill="#fff0c8" />
                    <path d="M145 35q19 13 27 31-14 7-27 4Z" fill="#f3d9a4" />
                    <g fill="none" stroke="#c49f6a" strokeWidth="0.9" opacity="0.72">
                        <path d="M78 9q-2 20 1 41M109 9q2 18-1 40M34 26q-1 17 1 35M56 27q1 15-1 34" />
                        <path d="M68 29q26 7 54 0M23 44q22 6 45 0" />
                    </g>
                    <path
                        d="M63 13q31-9 62 0M68 46q26 10 52-1M20 30q27-8 50 0M24 57q22 8 43 0"
                        fill="none"
                        stroke="#80583b"
                        strokeWidth="1.8"
                    />
                    <path d="M94-4v88M47 18v67M145 24v58" stroke="#5b3623" strokeWidth="3" />
                    <path d="m96-3 21 7-21 7Z" fill="#c76b32" />
                    <path d="M11 82q4-17 14-25l24 5 7 23Z" fill="#7b4829" />
                    <path d="m134 84 14-23 17 9 6 8Z" fill="#754226" />
                    <path
                        d="M18 66q15 4 31 3m99-1q9 4 18 6"
                        fill="none"
                        stroke="#d4a05c"
                        strokeWidth="1.8"
                    />
                    <g stroke="#684128" strokeWidth="1.1">
                        <rect x="69" y="73" width="13" height="10" rx="1.5" fill="#b77a42" />
                        <rect x="84" y="71" width="15" height="12" rx="1.5" fill="#c18749" />
                        <rect x="101" y="74" width="13" height="9" rx="1.5" fill="#a96c39" />
                        <ellipse cx="122" cy="78" rx="5" ry="6" fill="#b9793f" />
                        <path d="M75.5 73v10M84 77h15M107.5 74v9M117 78h10" fill="none" />
                    </g>
                    <path
                        d="M6 79c43 10 106 11 165-6-3 12-8 21-17 27-37 14-93 15-130 1C15 96 9 88 6 79Z"
                        fill="url(#carrack-wood-hull)"
                    />
                    <path
                        d="M17 84c43 8 97 8 145-4M24 92c39 9 91 8 132-4"
                        fill="none"
                        stroke="#d4a05c"
                        strokeWidth="1.8"
                        opacity="0.88"
                    />
                    <path
                        d="M24 92c39 10 91 9 132-4-2 5-5 9-9 12-35 11-85 12-119 1Z"
                        fill="#432d23"
                        opacity="0.72"
                    />
                    <g fill="#f1c46f" opacity="0.82">
                        <circle cx="52" cy="91" r="1.6" />
                        <circle cx="78" cy="94" r="1.6" />
                        <circle cx="105" cy="94" r="1.6" />
                        <circle cx="132" cy="91" r="1.6" />
                    </g>
                </g>
                {reducedMotion ? null : (
                    <animateTransform
                        attributeName="transform"
                        type="rotate"
                        values={shipPitchValues}
                        keyTimes={shipKeyTimes}
                        calcMode="linear"
                        dur={farWave.duration}
                        repeatCount="indefinite"
                    />
                )}
            </g>
        </g>
    );
}

function WaveLayer({
    spec,
    reducedMotion,
}: {
    readonly spec: WaveSpec;
    readonly reducedMotion: boolean;
}) {
    const area = waveArea(spec);
    const line = waveLine(spec);
    const foam = waveFoam(spec);
    const from = spec.direction === "left" ? "0 0" : `${-VIEWBOX_WIDTH} 0`;
    const to = spec.direction === "left" ? `${-VIEWBOX_WIDTH} 0` : "0 0";

    return (
        <g opacity={spec.opacity} transform={reducedMotion ? `translate(${from})` : undefined}>
            {[0, VIEWBOX_WIDTH].map((offset) => (
                <g key={offset} transform={`translate(${offset} 0)`}>
                    <path d={area} fill={spec.fill} />
                    <path d={foam} fill={spec.crest} opacity="0.3" />
                    <path
                        d={line}
                        fill="none"
                        stroke={spec.crest}
                        strokeWidth={spec.crestWidth}
                        strokeLinecap="round"
                    />
                </g>
            ))}
            {reducedMotion ? null : (
                <animateTransform
                    attributeName="transform"
                    type="translate"
                    from={from}
                    to={to}
                    dur={spec.duration}
                    repeatCount="indefinite"
                />
            )}
        </g>
    );
}

export function OceanBackdrop() {
    const reducedMotion = useMediaQuery("(prefers-reduced-motion: reduce)");

    return (
        <Box
            aria-hidden="true"
            sx={{
                position: "absolute",
                inset: 0,
                overflow: "hidden",
                bgcolor: "#56bce0",
                pointerEvents: "none",
            }}
        >
            <svg
                viewBox={`0 0 ${VIEWBOX_WIDTH} ${VIEWBOX_HEIGHT}`}
                preserveAspectRatio="xMidYMid slice"
                focusable="false"
                style={{ display: "block", width: "100%", height: "100%" }}
            >
                <defs>
                    <linearGradient id="carrack-sky" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0" stopColor="#1685c8" />
                        <stop offset="0.35" stopColor="#4bb2dc" />
                        <stop offset="0.51" stopColor="#9bd8e8" />
                        <stop offset="0.62" stopColor="#e7f2ed" />
                        <stop offset="1" stopColor="#68c4d8" />
                    </linearGradient>
                    <radialGradient
                        id="carrack-sunlight"
                        cx="285"
                        cy="150"
                        r="470"
                        gradientUnits="userSpaceOnUse"
                    >
                        <stop stopColor="#fff8d0" stopOpacity="0.98" />
                        <stop offset="0.16" stopColor="#ffdb7e" stopOpacity="0.42" />
                        <stop offset="0.48" stopColor="#fff3c5" stopOpacity="0.12" />
                        <stop offset="1" stopColor="#f3fbff" stopOpacity="0" />
                    </radialGradient>
                    <radialGradient id="carrack-horizon" cx="50%" cy="50%" r="50%">
                        <stop stopColor="#fff9dc" stopOpacity="0.66" />
                        <stop offset="0.42" stopColor="#b7e4df" stopOpacity="0.3" />
                        <stop offset="1" stopColor="#398da9" stopOpacity="0" />
                    </radialGradient>
                    <linearGradient id="carrack-ocean-far" x1="0" y1="0" x2="0" y2="1">
                        <stop stopColor="#4bbec5" />
                        <stop offset="1" stopColor="#147ca0" />
                    </linearGradient>
                    <linearGradient id="carrack-ocean-middle" x1="0" y1="0" x2="0" y2="1">
                        <stop stopColor="#24aac0" />
                        <stop offset="0.7" stopColor="#0b78a0" />
                        <stop offset="1" stopColor="#07557a" />
                    </linearGradient>
                    <linearGradient id="carrack-ocean-swell" x1="0" y1="0" x2="0" y2="1">
                        <stop stopColor="#139fbd" />
                        <stop offset="0.48" stopColor="#0b78a3" />
                        <stop offset="1" stopColor="#064b72" />
                    </linearGradient>
                    <linearGradient id="carrack-ocean-near" x1="0" y1="0" x2="0" y2="1">
                        <stop stopColor="#0b91b7" />
                        <stop offset="0.35" stopColor="#096b94" />
                        <stop offset="1" stopColor="#043b5c" />
                    </linearGradient>
                    <linearGradient id="carrack-ocean-foreground" x1="0" y1="0" x2="0" y2="1">
                        <stop stopColor="#08789e" />
                        <stop offset="0.56" stopColor="#055b80" />
                        <stop offset="1" stopColor="#03314f" />
                    </linearGradient>
                    <linearGradient id="carrack-wood-hull" x1="0" y1="0" x2="0" y2="1">
                        <stop stopColor="#9a5a31" />
                        <stop offset="0.48" stopColor="#704025" />
                        <stop offset="1" stopColor="#3d281e" />
                    </linearGradient>
                    <linearGradient id="carrack-canvas-sail" x1="0" y1="0" x2="1" y2="1">
                        <stop stopColor="#fff7dc" />
                        <stop offset="1" stopColor="#e9cf9f" />
                    </linearGradient>
                    <filter
                        id="carrack-cloud-field"
                        x="-10%"
                        y="-20%"
                        width="120%"
                        height="150%"
                        colorInterpolationFilters="sRGB"
                    >
                        <feTurbulence
                            type="fractalNoise"
                            baseFrequency="0.003 0.014"
                            numOctaves="4"
                            seed="37"
                        />
                        <feGaussianBlur stdDeviation="13" />
                        <feColorMatrix
                            type="matrix"
                            values="0 0 0 0 0.78  0 0 0 0 0.88  0 0 0 0 0.91  0 0 0 0.34 0"
                        />
                    </filter>
                    <filter
                        id="carrack-water-grain"
                        x="-5%"
                        y="-5%"
                        width="110%"
                        height="110%"
                        colorInterpolationFilters="sRGB"
                    >
                        <feTurbulence
                            type="fractalNoise"
                            baseFrequency="0.012 0.075"
                            numOctaves="2"
                            seed="19"
                        />
                        <feColorMatrix
                            type="matrix"
                            values="0 0 0 0 0.62  0 0 0 0 0.86  0 0 0 0 0.91  0 0 0 0.18 0"
                        />
                    </filter>
                    <filter id="carrack-soft-cloud" x="-30%" y="-50%" width="160%" height="200%">
                        <feGaussianBlur stdDeviation="7" />
                    </filter>
                </defs>

                <rect width={VIEWBOX_WIDTH} height={VIEWBOX_HEIGHT} fill="url(#carrack-sky)" />
                <rect width={VIEWBOX_WIDTH} height={VIEWBOX_HEIGHT} fill="url(#carrack-sunlight)" />
                <circle
                    cx="285"
                    cy="150"
                    r="82"
                    fill="#ffe39a"
                    opacity="0.16"
                    filter="url(#carrack-soft-cloud)"
                />
                <circle cx="285" cy="150" r="43" fill="#fff4bd" opacity="0.94" />
                <rect
                    x="-120"
                    y="70"
                    width="1840"
                    height="350"
                    filter="url(#carrack-cloud-field)"
                    opacity="0.16"
                />
                <g fill="#ffffff" opacity="0.4" filter="url(#carrack-soft-cloud)">
                    <ellipse cx="970" cy="128" rx="120" ry="23" />
                    <ellipse cx="1055" cy="117" rx="91" ry="31" />
                    <ellipse cx="1128" cy="133" rx="115" ry="21" />
                    <ellipse cx="560" cy="235" rx="82" ry="17" />
                    <ellipse cx="620" cy="226" rx="61" ry="24" />
                    <ellipse cx="675" cy="237" rx="76" ry="15" />
                </g>
                <ellipse cx="800" cy="414" rx="610" ry="165" fill="url(#carrack-horizon)" />
                <DistantCarrack reducedMotion={reducedMotion} />
                {waves.map((spec) => (
                    <WaveLayer key={spec.id} spec={spec} reducedMotion={reducedMotion} />
                ))}
                <g stroke="#fff0b0" strokeWidth="2.6" strokeLinecap="round">
                    {sunlightSparkles.map((sparkle) => (
                        <line
                            key={sparkle.y}
                            x1={sparkle.x1}
                            x2={sparkle.x2}
                            y1={sparkle.y}
                            y2={sparkle.y}
                            opacity={sparkle.opacity}
                        />
                    ))}
                </g>
                <rect
                    y="405"
                    width={VIEWBOX_WIDTH}
                    height={VIEWBOX_HEIGHT - 405}
                    filter="url(#carrack-water-grain)"
                    opacity="0.1"
                />
            </svg>
            <Box
                sx={{
                    position: "absolute",
                    inset: 0,
                    background:
                        "radial-gradient(circle at 50% 44%, transparent 0 36%, rgba(1, 35, 56, 0.04) 74%, rgba(1, 24, 43, 0.18) 100%), linear-gradient(90deg, rgba(5, 55, 78, 0.06), transparent 34% 66%, rgba(5, 55, 78, 0.06))",
                }}
            />
        </Box>
    );
}
