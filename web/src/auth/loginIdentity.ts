export function passwordManagerIdentity(account: string, environment: string): string {
    return account === "" || environment === "unknown" ? "" : `${account}@${environment}`;
}

export function resolvePasswordManagerIdentity(
    identity: string,
    account: string,
    environment: string,
): string | null {
    return identity === passwordManagerIdentity(account, environment) ? account : null;
}
