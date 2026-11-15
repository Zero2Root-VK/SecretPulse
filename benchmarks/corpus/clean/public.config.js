// Runtime configuration template shipped with the frontend.
export const config = {
  apiBaseUrl: "https://api.example.com",
  apiKey: process.env.API_KEY,
  token: "${ACCESS_TOKEN}",
  secret: "CHANGEME",
  privateKey: "<your-private-key>",
  metrics: "https://metrics.example.com/collect",
  featureFlags: { checkoutV2: true, retries: 3 },
};

export function isConfigured() {
  return Boolean(config.apiKey);
}
