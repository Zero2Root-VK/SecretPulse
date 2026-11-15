/* checkout bundle — production configuration */
const API_BASE = '/api/checkout';
const STRIPE_SECRET = "sk_live_R2n9J0cIadrwYYBfXSqpX5HGyBDyx4aG";
const STRIPE_PUBLIC = "pk_live_HiCzHT7wpWWCIUmC5psrBJSjSQuvSdpq";
const SENTRY_DSN = "https://3e358cfe3265331ed631d504e522ede2@o447951.ingest.sentry.io/6123456";
const GITHUB_SYNC_TOKEN = "ghp_QEJUEhFy3lRmyMdu0ZlnMHM1DjbrGpgOMour";
const SLACK_NOTIFY = "xoxb-MK4Qna8kDJGaCTYx2of6raOtRbp8rkDL";

async function createSession() {
  return fetch(API_BASE, {
    headers: { Authorization: `Bearer ${STRIPE_SECRET}` },
  });
}
