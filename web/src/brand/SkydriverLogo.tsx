import type { SVGProps } from "react";

interface SkydriverMarkProps extends SVGProps<SVGSVGElement> {
    readonly title?: string;
}

export function SkydriverMark({ title, ...props }: SkydriverMarkProps) {
    return (
        <svg
            viewBox="0 0 332 248"
            role={title === undefined ? undefined : "img"}
            aria-hidden={title === undefined ? true : undefined}
            focusable="false"
            {...props}
        >
            {title === undefined ? null : <title>{title}</title>}
            <image href="/skydriver-mark.png" width="332" height="248" />
        </svg>
    );
}
