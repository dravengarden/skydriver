import {
    createCardeaEmailLogin,
    type CardeaEmailLoginElement,
    type CardeaLoginState,
    type CardeaLoginSubmitDetail,
} from "@dravengarden/cardea-consumer-ui";
import { Box } from "@mui/material";
import { useEffect, useRef } from "react";

interface CardeaLoginFormProps {
    readonly state: CardeaLoginState;
    readonly retrySeconds: number;
    readonly remainingLabel: string | null;
    readonly onSubmit: (detail: CardeaLoginSubmitDetail) => Promise<string | null>;
}

export function CardeaLoginForm({
    state,
    retrySeconds,
    remainingLabel,
    onSubmit,
}: CardeaLoginFormProps) {
    const host = useRef<HTMLDivElement>(null);
    const element = useRef<CardeaEmailLoginElement | null>(null);
    const submit = useRef(onSubmit);
    submit.current = onSubmit;

    useEffect(() => {
        const login = createCardeaEmailLogin("skydriver");
        login.onSubmit = (detail) => {
            void submit.current(detail).then((authenticationUrl) => {
                if (detail.method !== "passkey") return;
                if (authenticationUrl === null) login.passkeyUnavailable();
                else login.authenticationUrl = authenticationUrl;
            });
        };
        host.current?.replaceChildren(login);
        element.current = login;
        return () => {
            login.onSubmit = null;
            login.remove();
            element.current = null;
        };
    }, []);

    useEffect(() => {
        if (element.current === null) {
            return;
        }
        element.current.state = state;
        element.current.retrySeconds = retrySeconds;
        element.current.remainingLabel = remainingLabel;
    }, [remainingLabel, retrySeconds, state]);

    return (
        <Box
            ref={host}
            sx={{
                "--cardea-action": "linear-gradient(105deg, #176d9b, #2d70d6)",
                "--cardea-action-hover": "linear-gradient(105deg, #145f88, #2864bf)",
                "--cardea-action-text": "#fff",
            }}
        />
    );
}
