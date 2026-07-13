import { useId, type SVGProps } from "react";

interface CarrackMarkProps extends SVGProps<SVGSVGElement> {
    readonly title?: string;
}

export function CarrackMark({ title, ...props }: CarrackMarkProps) {
    const gradientId = `carrack-mark-${useId().replaceAll(":", "")}`;

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
                <linearGradient id={gradientId} x1="9" y1="6" x2="55" y2="58">
                    <stop stopColor="#123f66" />
                    <stop offset="1" stopColor="#061827" />
                </linearGradient>
            </defs>
            <rect x="2" y="2" width="60" height="60" rx="17" fill={`url(#${gradientId})`} />
            <path d="M30.5 9.5h3v32h-3z" fill="#b8efff" />
            <path
                d="M28.5 14.2v22.9c-6-.2-11.7-1.1-16.9-2.7 4.2-10 9.9-16.7 16.9-20.2Z"
                fill="#2bc6e7"
            />
            <path
                d="M35.5 13.1c8.2 3.8 13.7 10.9 16.2 21.3-5.1 1.5-10.5 2.4-16.2 2.7v-24Z"
                fill="#f3fbff"
            />
            <path
                d="M9.8 39.4c7 1.5 14.4 2.2 22.2 2.2s15.2-.7 22.2-2.2l-5 9.2c-4.8 4.5-10.6 6.8-17.2 6.8s-12.4-2.3-17.2-6.8l-5-9.2Z"
                fill="#f3fbff"
            />
            <path
                d="M13.4 46.1c4.9-2.7 9.4-2.7 14.3 0 3.1 1.7 5.5 1.7 8.6 0 4.9-2.7 9.4-2.7 14.3 0"
                fill="none"
                stroke="#2bc6e7"
                strokeWidth="2.8"
                strokeLinecap="round"
            />
        </svg>
    );
}
