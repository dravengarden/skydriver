export function durableObjectMigrationConfig(config, environmentName) {
    if (environmentName !== "dev" && environmentName !== "prod") {
        throw new Error("deployment environment must be dev or prod");
    }
    const deploymentConfig = structuredClone(config);
    const environment = deploymentConfig.env?.[environmentName];
    if (environment === undefined) {
        throw new Error(`${environmentName} deployment environment is missing`);
    }

    // `wrangler deploy` is required to apply a Durable Object migration, but
    // routes and Cron schedules are independent control-plane resources. Keep
    // the existing custom domain and schedules untouched; the caller verifies
    // and synchronizes schedules separately after the Worker is accepted.
    delete deploymentConfig.route;
    delete deploymentConfig.routes;
    delete deploymentConfig.triggers;
    delete environment.route;
    delete environment.routes;
    delete environment.triggers;
    return deploymentConfig;
}
