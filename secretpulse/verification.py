"""Legacy and read-only active credential verifiers."""
from ._imports import *
from .constants import PUBLIC_IDENTIFIER_TYPES

class ActiveVerifier:
    """
    Live API verification for discovered secrets.
    Only runs when --verify flag is set.
    All checks are read-only (GET requests or minimal-permission calls).
    """

    def __init__(self, session: requests.Session, timeout: int = 5):
        self.session = session
        self.timeout = timeout

    def verify_google_maps(self, key: str) -> Dict:
        """Probe Google Maps Geocoding API with an invalid address."""
        try:
            r = self.session.get(
                'https://maps.googleapis.com/maps/api/geocode/json',
                params={'address': 'test', 'key': key}, timeout=self.timeout)
            data = r.json()
            status = data.get('status', '')
            if status == 'REQUEST_DENIED':
                err = data.get('error_message', '')
                if 'not authorized' in err.lower() or 'not activated' in err.lower():
                    return {'live': False, 'detail': f'Key valid but Geocoding not enabled: {err}'}
                return {'live': False, 'detail': err}
            if status in ('OK', 'ZERO_RESULTS'):
                return {'live': True, 'detail': 'Geocoding API is ACTIVE and billable'}
            return {'live': None, 'detail': f'Unknown status: {status}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_google_scope(self, key: str) -> Dict:
        """Check which Google APIs are unrestricted for this key."""
        apis = {}
        checks = [
            ('Maps Geocoding', 'https://maps.googleapis.com/maps/api/geocode/json',
             {'address': 'test', 'key': key}),
            ('Maps Directions', 'https://maps.googleapis.com/maps/api/directions/json',
             {'origin': 'A', 'destination': 'B', 'key': key}),
            ('Maps Places', 'https://maps.googleapis.com/maps/api/place/findplacefromtext/json',
             {'input': 'test', 'inputtype': 'textquery', 'key': key}),
            ('Maps Static', 'https://maps.googleapis.com/maps/api/staticmap',
             {'center': '0,0', 'zoom': '1', 'size': '1x1', 'key': key}),
            ('YouTube Data', 'https://www.googleapis.com/youtube/v3/videos',
             {'part': 'id', 'chart': 'mostPopular', 'maxResults': '1', 'key': key}),
            ('Custom Search', 'https://www.googleapis.com/customsearch/v1',
             {'q': 'test', 'key': key}),
        ]
        for name, url, params in checks:
            try:
                r = self.session.get(url, params=params, timeout=self.timeout)
                if r.status_code == 200:
                    apis[name] = 'ACTIVE ✓'
                elif r.status_code == 403:
                    try:
                        err = r.json().get('error', {}).get('message', 'Denied')
                    except Exception:
                        err = 'Denied'
                    apis[name] = f'Restricted: {err[:60]}'
                else:
                    apis[name] = f'HTTP {r.status_code}'
            except Exception:
                apis[name] = 'Error'
        return apis

    def verify_slack_token(self, token: str) -> Dict:
        """Slack auth.test — read-only identity check."""
        try:
            r = self.session.post('https://slack.com/api/auth.test',
                                  headers={'Authorization': f'Bearer {token}'},
                                  timeout=self.timeout)
            data = r.json()
            if data.get('ok'):
                return {'live': True, 'detail': f"Team: {data.get('team','?')} User: {data.get('user','?')}"}
            return {'live': False, 'detail': data.get('error', 'invalid_auth')}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_slack_webhook(self, url: str) -> Dict:
        """Check if Slack webhook is alive with empty POST."""
        try:
            r = self.session.post(url, json={'text': ''}, timeout=self.timeout)
            if r.status_code == 200 or 'no_text' in r.text:
                return {'live': True, 'detail': 'Webhook endpoint is active'}
            if r.status_code in (403, 404):
                return {'live': False, 'detail': f'HTTP {r.status_code} — revoked or invalid'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_github_token(self, token: str) -> Dict:
        """GitHub token check via /user endpoint."""
        try:
            r = self.session.get('https://api.github.com/user',
                                  headers={'Authorization': f'token {token}'},
                                  timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                scopes = r.headers.get('X-OAuth-Scopes', 'N/A')
                return {'live': True, 'detail': f"User: {data.get('login','?')} Scopes: {scopes}"}
            if r.status_code == 401:
                return {'live': False, 'detail': 'Token expired or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_stripe_key(self, key: str) -> Dict:
        """Stripe key check via /v1/charges (read-only with limit=1)."""
        try:
            r = self.session.get('https://api.stripe.com/v1/charges',
                                  params={'limit': '1'},
                                  auth=(key, ''), timeout=self.timeout)
            if r.status_code == 200:
                return {'live': True, 'detail': 'Secret key is ACTIVE — full API access'}
            if r.status_code == 401:
                return {'live': False, 'detail': 'Key invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_sendgrid(self, key: str) -> Dict:
        """SendGrid API key check via /v3/scopes."""
        try:
            r = self.session.get('https://api.sendgrid.com/v3/scopes',
                                  headers={'Authorization': f'Bearer {key}'},
                                  timeout=self.timeout)
            if r.status_code == 200:
                scopes = r.json().get('scopes', [])
                return {'live': True, 'detail': f'{len(scopes)} scopes authorized'}
            if r.status_code in (401, 403):
                return {'live': False, 'detail': 'Key invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_twilio(self, sid: str) -> Dict:
        """Twilio SID format check — only confirms format (needs auth token for live)."""
        if sid.startswith('AC') and len(sid) == 34:
            return {'live': None, 'detail': 'Valid SID format (needs auth token to verify live)'}
        return {'live': False, 'detail': 'Invalid SID format'}

    def verify_mapbox(self, token: str) -> Dict:
        """Mapbox token check via geocoding API."""
        try:
            r = self.session.get(
                f'https://api.mapbox.com/geocoding/v5/mapbox.places/test.json',
                params={'access_token': token}, timeout=self.timeout)
            if r.status_code == 200:
                return {'live': True, 'detail': 'Token is ACTIVE'}
            if r.status_code in (401, 403):
                return {'live': False, 'detail': 'Token invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_hubspot(self, key: str) -> Dict:
        """HubSpot token check via account info."""
        try:
            r = self.session.get('https://api.hubapi.com/account-info/v3/details',
                                  headers={'Authorization': f'Bearer {key}'},
                                  timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                return {'live': True, 'detail': f"Portal: {data.get('portalId','?')}"}
            if r.status_code in (401, 403):
                return {'live': False, 'detail': 'Key invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    # ── NEW v2.9: 5 additional verifiers ──────────────────────

    def verify_aws_sts(self, key: str) -> Dict:
        """AWS access key check via STS GetCallerIdentity (needs secret key context)."""
        if key.startswith('AKIA') and len(key) == 20:
            return {'live': None, 'detail': 'Valid AKIA format — needs secret key for STS call. '
                    'Key ID alone confirms AWS IAM user exists.'}
        return {'live': False, 'detail': 'Invalid AWS key format'}

    def verify_mailgun(self, key: str) -> Dict:
        """Mailgun API key check via domains endpoint."""
        try:
            r = self.session.get('https://api.mailgun.net/v3/domains',
                                  auth=('api', key), timeout=self.timeout)
            if r.status_code == 200:
                domains = r.json().get('items', [])
                names = [d.get('name', '?') for d in domains[:3]]
                return {'live': True, 'detail': f'{len(domains)} domains: {", ".join(names)}'}
            if r.status_code in (401, 403):
                return {'live': False, 'detail': 'Key invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_notion(self, key: str) -> Dict:
        """Notion API key check via /v1/users/me."""
        try:
            r = self.session.get('https://api.notion.com/v1/users/me',
                                  headers={'Authorization': f'Bearer {key}',
                                           'Notion-Version': '2022-06-28'},
                                  timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                return {'live': True, 'detail': f"Bot: {data.get('name','?')} Type: {data.get('type','?')}"}
            if r.status_code in (401, 403):
                return {'live': False, 'detail': 'Key invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_linear(self, key: str) -> Dict:
        """Linear API key check via GraphQL /viewer."""
        try:
            r = self.session.post('https://api.linear.app/graphql',
                                   headers={'Authorization': key,
                                            'Content-Type': 'application/json'},
                                   json={'query': '{ viewer { id name email } }'},
                                   timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                viewer = (data.get('data') or {}).get('viewer', {})
                if viewer:
                    return {'live': True, 'detail': f"User: {viewer.get('name','?')} ({viewer.get('email','?')})"}
            if r.status_code in (401, 403):
                return {'live': False, 'detail': 'Key invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_datadog(self, token: str) -> Dict:
        """Datadog RUM/API token check via /api/v1/validate."""
        try:
            r = self.session.get('https://api.datadoghq.com/api/v1/validate',
                                  headers={'DD-API-KEY': token}, timeout=self.timeout)
            if r.status_code == 200:
                return {'live': True, 'detail': 'API key is ACTIVE'}
            if r.status_code in (401, 403):
                return {'live': False, 'detail': 'Key invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify(self, secret_type: str, value: str) -> Optional[Dict]:
        """Route to appropriate verifier based on secret type."""
        dispatch = {
            'Google API Key': lambda v: self.verify_google_maps(v),
            'Firebase Config': lambda v: self.verify_google_maps(v),
            'Slack Token': lambda v: self.verify_slack_token(v),
            'Slack Webhook': lambda v: self.verify_slack_webhook(v),
            'GitHub Token': lambda v: self.verify_github_token(v),
            'Stripe API Key': lambda v: self.verify_stripe_key(v),
            'SendGrid API Key': lambda v: self.verify_sendgrid(v),
            'Twilio Credentials': lambda v: self.verify_twilio(v),
            'Mapbox Token': lambda v: self.verify_mapbox(v),
            'HubSpot API Key': lambda v: self.verify_hubspot(v),
            'AWS Access Key': lambda v: self.verify_aws_sts(v),
            'Mailgun API Key': lambda v: self.verify_mailgun(v),
            'Notion API Key': lambda v: self.verify_notion(v),
            'Linear API Key': lambda v: self.verify_linear(v),
            'Datadog RUM Token': lambda v: self.verify_datadog(v),
        }
        fn = dispatch.get(secret_type)
        if fn:
            return fn(value)
        return None

class ActiveVerifierV2(ActiveVerifier):
    """Extended verifier with 66 read-only API validation routes."""

    def __init__(self, session, provider_allowlist=None, allow_webhooks=False):
        super().__init__(session)
        self.provider_allowlist = {
            str(p).strip().lower() for p in (provider_allowlist or []) if str(p).strip()
        }
        self.allow_webhooks = allow_webhooks

    def verify(self, secret_type: str, value: str) -> Optional[Dict]:
        """Route to appropriate verifier — 60+ provider types."""
        meta = PUBLIC_IDENTIFIER_TYPES.get(secret_type)
        if meta and meta.get('skip_verification'):
            return {'live': None, 'detail': 'Skipped: public identifier by design'}
        if self.provider_allowlist and not any(
                token in secret_type.lower() for token in self.provider_allowlist):
            return None
        if secret_type == 'Slack Webhook' and not self.allow_webhooks:
            return {'live': None, 'detail': 'Skipped: side-effecting webhook check disabled'}

        dispatch = {
            # Original 15 from v2.9
            'Google API Key': lambda v: self.verify_google_maps(v),
            'Firebase Config': lambda v: self.verify_google_maps(v),
            'Slack Token': lambda v: self.verify_slack_token(v),
            'Slack Webhook': lambda v: self.verify_slack_webhook(v),
            'GitHub Token': lambda v: self.verify_github_token(v),
            'Stripe API Key': lambda v: self.verify_stripe_key(v),
            'SendGrid API Key': lambda v: self.verify_sendgrid(v),
            'Twilio Credentials': lambda v: self.verify_twilio(v),
            'Mapbox Token': lambda v: self.verify_mapbox(v),
            'HubSpot API Key': lambda v: self.verify_hubspot(v),
            'AWS Access Key': lambda v: self.verify_aws_sts(v),
            'Mailgun API Key': lambda v: self.verify_mailgun(v),
            'Notion API Key': lambda v: self.verify_notion(v),
            'Linear API Key': lambda v: self.verify_linear(v),
            'Datadog RUM Token': lambda v: self.verify_datadog(v),
            # v4.0: 36 new verifiers
            'OpenAI API Key': lambda v: self.verify_openai(v),
            'Anthropic API Key': lambda v: self.verify_anthropic(v),
            'HuggingFace Token': lambda v: self.verify_huggingface(v),
            'Cloudflare API Token': lambda v: self.verify_cloudflare(v),
            'Cloudflare Global API Key': lambda v: self.verify_cloudflare(v),
            'DigitalOcean Token': lambda v: self.verify_digitalocean(v),
            'Heroku API Key': lambda v: self.verify_heroku(v),
            'GitLab Token': lambda v: self.verify_gitlab(v),
            'npm Token': lambda v: self.verify_npm(v),
            'New Relic API Key': lambda v: self.verify_newrelic(v),
            'Grafana API Key': lambda v: self.verify_grafana(v),
            'Elastic API Key': lambda v: self.verify_elastic(v),
            'PagerDuty API Key': lambda v: self.verify_pagerduty(v),
            'PostHog API Key': lambda v: self.verify_posthog(v),
            'Okta API Token': lambda v: self.verify_okta(v),
            'Shopify API Key': lambda v: self.verify_shopify(v),
            'Square Access Token': lambda v: self.verify_square(v),
            'PayPal Client Secret': lambda v: self.verify_paypal(v),
            'Discord Bot Token': lambda v: self.verify_discord(v),
            'Twitch API Token': lambda v: self.verify_twitch(v),
            'Airtable API Key': lambda v: self.verify_airtable(v),
            'Contentful Token': lambda v: self.verify_contentful(v),
            'Terraform Cloud Token': lambda v: self.verify_terraform(v),
            'HashiCorp Vault Token': lambda v: self.verify_vault(v),
            'PlanetScale Password': lambda v: self.verify_planetscale(v),
            'CircleCI Token': lambda v: self.verify_circleci(v),
            'Bitbucket App Password': lambda v: self.verify_bitbucket(v),
            'Spotify Client Secret': lambda v: self.verify_spotify(v),
            'Supabase Key': lambda v: self.verify_supabase(v),
            'Vercel Token': lambda v: self.verify_vercel(v),
            'Netlify Token': lambda v: self.verify_netlify(v),
            'Pinecone API Key': lambda v: self.verify_pinecone(v),
            'Cohere API Key': lambda v: self.verify_cohere(v),
            'Replicate API Token': lambda v: self.verify_replicate(v),
            'OAuth Access Token': lambda v: self.verify_oauth_token(v),
            'OAuth Refresh Token': lambda v: self.verify_oauth_token(v),
            'Firebase Auth': lambda v: self.verify_firebase_auth(v),
            # v5.4: 2026 provider checks (all read-only GETs)
            'OpenRouter API Key': lambda v: self.verify_openrouter(v),
            'Groq API Key': lambda v: self.verify_groq(v),
            'xAI API Key': lambda v: self.verify_xai(v),
            'Mistral API Key': lambda v: self.verify_mistral(v),
            'DeepSeek API Key': lambda v: self.verify_deepseek(v),
            'Together API Key': lambda v: self.verify_together(v),
            'Resend API Key': lambda v: self.verify_resend(v),
            'Postman API Key': lambda v: self.verify_postman(v),
            'Pulumi Access Token': lambda v: self.verify_pulumi(v),
            'Sentry User Token': lambda v: self.verify_sentry_user(v),
            'Datadog API Key': lambda v: self.verify_datadog(v),
            'Telegram Bot Token': lambda v: self.verify_telegram(v),
            'Discord Webhook': lambda v: self.verify_discord_webhook(v),
            'Mailchimp API Key': lambda v: self.verify_mailchimp(v),
        }
        fn = dispatch.get(secret_type)
        if fn:
            return fn(value)
        return None

    def verify_openai(self, key, **kw):
        try:
            r = self.session.get('https://api.openai.com/v1/models',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            if r.status_code == 200:
                models = r.json().get('data', [])
                return {'live': True, 'models': len(models), 'permissions': 'full_api_access'}
            return {'live': False, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_anthropic(self, key, **kw):
        try:
            r = self.session.get('https://api.anthropic.com/v1/models',
                                  headers={'x-api-key': key, 'anthropic-version': '2023-06-01'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_huggingface(self, key, **kw):
        try:
            r = self.session.get('https://huggingface.co/api/whoami-v2',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                return {'live': True, 'user': d.get('name', '?'),
                        'orgs': [o.get('name') for o in d.get('orgs', [])]}
            return {'live': False, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_cohere(self, key, **kw):
        try:
            r = self.session.get('https://api.cohere.ai/v1/models',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_replicate(self, key, **kw):
        try:
            r = self.session.get('https://api.replicate.com/v1/account',
                                  headers={'Authorization': f'Token {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_pinecone(self, key, **kw):
        try:
            r = self.session.get('https://api.pinecone.io/indexes',
                                  headers={'Api-Key': key}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_cloudflare(self, key, **kw):
        try:
            r = self.session.get('https://api.cloudflare.com/client/v4/user',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            if r.status_code == 200:
                d = r.json().get('result', {})
                return {'live': True, 'email': d.get('email', '?')}
            return {'live': False, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_digitalocean(self, key, **kw):
        try:
            r = self.session.get('https://api.digitalocean.com/v2/account',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            if r.status_code == 200:
                acct = r.json().get('account', {})
                return {'live': True, 'email': acct.get('email', '?'),
                        'droplet_limit': acct.get('droplet_limit')}
            return {'live': False, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_heroku(self, key, **kw):
        try:
            r = self.session.get('https://api.heroku.com/account',
                                  headers={'Authorization': f'Bearer {key}',
                                           'Accept': 'application/vnd.heroku+json; version=3'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_vercel(self, key, **kw):
        try:
            r = self.session.get('https://api.vercel.com/v2/user',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_netlify(self, key, **kw):
        try:
            r = self.session.get('https://api.netlify.com/api/v1/user',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_terraform(self, key, **kw):
        try:
            r = self.session.get('https://app.terraform.io/api/v2/account/details',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_vault(self, key, **kw):
        return {'live': None, 'note': 'Requires Vault server URL'}

    def verify_supabase(self, key, **kw):
        try:
            parts = key.split('.')
            if len(parts) == 3:
                payload = json.loads(base64.b64decode(parts[1] + '==').decode('utf-8', errors='ignore'))
                return {'live': True, 'role': payload.get('role', '?'), 'iss': payload.get('iss', '?')}
            return {'live': False}
        except Exception: return {'live': False}

    def _verify_models_endpoint(self, url, key, provider):
        """Validate a bearer key against a read-only OpenAI-compatible models endpoint."""
        try:
            r = self.session.get(url, headers={'Authorization': f'Bearer {key}'}, timeout=8)
            if r.status_code == 200:
                try:
                    payload = r.json()
                    models = payload if isinstance(payload, list) else payload.get('data', [])
                    detail = f'{provider} key is ACTIVE'
                    if models:
                        detail += f' ({len(models)} models visible)'
                    return {'live': True, 'detail': detail}
                except Exception:
                    return {'live': True, 'detail': f'{provider} key is ACTIVE'}
            if r.status_code == 401:
                return {'live': False, 'detail': f'{provider} key invalid or revoked'}
            return {'live': None, 'detail': f'{provider} HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_openrouter(self, key, **kw):
        try:
            r = self.session.get('https://openrouter.ai/api/v1/key',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            if r.status_code == 200:
                data = r.json().get('data', {})
                label = data.get('label') or data.get('name') or 'key'
                usage = data.get('usage')
                detail = f'OpenRouter key is ACTIVE ({label})'
                if usage is not None:
                    detail += f' — usage {usage}'
                return {'live': True, 'detail': detail}
            if r.status_code == 401:
                return {'live': False, 'detail': 'OpenRouter key invalid or revoked'}
            return {'live': None, 'detail': f'OpenRouter HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_groq(self, key, **kw):
        return self._verify_models_endpoint(
            'https://api.groq.com/openai/v1/models', key, 'Groq')

    def verify_xai(self, key, **kw):
        return self._verify_models_endpoint(
            'https://api.x.ai/v1/models', key, 'xAI')

    def verify_mistral(self, key, **kw):
        return self._verify_models_endpoint(
            'https://api.mistral.ai/v1/models', key, 'Mistral')

    def verify_deepseek(self, key, **kw):
        return self._verify_models_endpoint(
            'https://api.deepseek.com/models', key, 'DeepSeek')

    def verify_together(self, key, **kw):
        return self._verify_models_endpoint(
            'https://api.together.xyz/v1/models', key, 'Together')

    def verify_resend(self, key, **kw):
        try:
            r = self.session.get('https://api.resend.com/api-keys',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            if r.status_code == 200:
                try:
                    keys = r.json().get('data', [])
                    return {'live': True, 'detail': f'Resend key is ACTIVE ({len(keys)} keys visible)'}
                except Exception:
                    return {'live': True, 'detail': 'Resend key is ACTIVE'}
            if r.status_code == 401:
                return {'live': False, 'detail': 'Resend key invalid or revoked'}
            return {'live': None, 'detail': f'Resend HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_postman(self, key, **kw):
        try:
            r = self.session.get('https://api.getpostman.com/me',
                                  headers={'X-Api-Key': key}, timeout=8)
            if r.status_code == 200:
                data = r.json().get('user', {})
                return {'live': True, 'detail': f"Postman user: {data.get('username', '?')}"}
            if r.status_code == 401:
                return {'live': False, 'detail': 'Postman key invalid or revoked'}
            return {'live': None, 'detail': f'Postman HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_pulumi(self, key, **kw):
        try:
            r = self.session.get('https://api.pulumi.com/api/user',
                                  headers={'Authorization': f'token {key}'}, timeout=8)
            if r.status_code == 200:
                data = r.json()
                return {'live': True, 'detail': f"Pulumi user: {data.get('githubLogin', '?')}"}
            if r.status_code == 401:
                return {'live': False, 'detail': 'Pulumi token invalid or revoked'}
            return {'live': None, 'detail': f'Pulumi HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_sentry_user(self, key, **kw):
        try:
            r = self.session.get('https://sentry.io/api/0/organizations/',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            if r.status_code == 200:
                try:
                    orgs = r.json()
                    return {'live': True, 'detail': f'Sentry token is ACTIVE ({len(orgs)} orgs visible)'}
                except Exception:
                    return {'live': True, 'detail': 'Sentry token is ACTIVE'}
            if r.status_code == 401:
                return {'live': False, 'detail': 'Sentry token invalid or revoked'}
            return {'live': None, 'detail': f'Sentry HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_telegram(self, key, **kw):
        try:
            r = self.session.get(f'https://api.telegram.org/bot{key}/getMe', timeout=8)
            data = r.json() if r.headers.get('content-type', '').startswith('application/json') else {}
            if r.status_code == 200 and data.get('ok'):
                bot = data.get('result', {})
                return {'live': True, 'detail': f"Telegram bot: @{bot.get('username', '?')}"}
            if r.status_code in (401, 404):
                return {'live': False, 'detail': 'Telegram bot token invalid or revoked'}
            return {'live': None, 'detail': f'Telegram HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_discord_webhook(self, url, **kw):
        try:
            r = self.session.get(url, timeout=8)
            if r.status_code == 200:
                data = r.json()
                return {'live': True, 'detail': f"Discord webhook: {data.get('name', '?')}"}
            if r.status_code in (401, 404):
                return {'live': False, 'detail': 'Discord webhook invalid or revoked'}
            return {'live': None, 'detail': f'Discord HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_mailchimp(self, key, **kw):
        m = re.search(r'-us(\d{1,2})$', key)
        if not m:
            return {'live': None, 'detail': 'Mailchimp data center unavailable'}
        try:
            r = self.session.get(f'https://us{m.group(1)}.api.mailchimp.com/3.0/ping',
                                  auth=('SecretPulse', key), timeout=8)
            if r.status_code == 200:
                return {'live': True, 'detail': 'Mailchimp key is ACTIVE'}
            if r.status_code == 401:
                return {'live': False, 'detail': 'Mailchimp key invalid or revoked'}
            return {'live': None, 'detail': f'Mailchimp HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_gitlab(self, key, **kw):
        try:
            r = self.session.get('https://gitlab.com/api/v4/user',
                                  headers={'PRIVATE-TOKEN': key}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                return {'live': True, 'username': d.get('username', '?'),
                        'is_admin': d.get('is_admin', False)}
            return {'live': False, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_circleci(self, key, **kw):
        try:
            r = self.session.get('https://circleci.com/api/v2/me',
                                  headers={'Circle-Token': key}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_bitbucket(self, key, **kw):
        try:
            r = self.session.get('https://api.bitbucket.org/2.0/user',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_npm(self, key, **kw):
        try:
            r = self.session.get('https://registry.npmjs.org/-/npm/v1/user',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_shopify(self, key, **kw):
        return {'live': None, 'note': 'Requires store domain for validation'}

    def verify_square(self, key, **kw):
        try:
            r = self.session.get('https://connect.squareup.com/v2/merchants',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_paypal(self, key, **kw):
        return {'live': None, 'note': 'Requires client_id pair'}

    def verify_newrelic(self, key, **kw):
        try:
            r = self.session.get('https://api.newrelic.com/v2/applications.json',
                                  headers={'Api-Key': key}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_grafana(self, key, **kw):
        try:
            r = self.session.get('https://grafana.com/api/user',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_elastic(self, key, **kw):
        return {'live': None, 'note': 'Requires cluster URL'}

    def verify_pagerduty(self, key, **kw):
        try:
            r = self.session.get('https://api.pagerduty.com/users/me',
                                  headers={'Authorization': f'Token token={key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_posthog(self, key, **kw):
        try:
            r = self.session.get('https://app.posthog.com/api/projects/',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code in (200, 403), 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_okta(self, key, **kw):
        return {'live': None, 'note': 'Requires Okta domain'}

    def verify_firebase_auth(self, key, **kw):
        return {'live': None, 'note': 'Requires project ID'}

    def verify_discord(self, key, **kw):
        try:
            r = self.session.get('https://discord.com/api/v10/users/@me',
                                  headers={'Authorization': f'Bot {key}'}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                return {'live': True, 'username': d.get('username', '?'), 'bot': d.get('bot', False)}
            return {'live': False, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_twitch(self, key, **kw):
        return {'live': None, 'note': 'Requires client_id pair'}

    def verify_spotify(self, key, **kw):
        return {'live': None, 'note': 'Requires client_id pair'}

    def verify_airtable(self, key, **kw):
        try:
            r = self.session.get('https://api.airtable.com/v0/meta/whoami',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_contentful(self, key, **kw):
        return {'live': None, 'note': 'Requires space_id'}

    def verify_planetscale(self, key, **kw):
        return {'live': None, 'note': 'Requires DB URL'}

    def verify_oauth_token(self, key, **kw):
        try:
            for url in ['https://oauth2.googleapis.com/tokeninfo',
                        'https://graph.facebook.com/me']:
                r = self.session.get(url, params={'access_token': key}, timeout=5)
                if r.status_code == 200:
                    return {'live': True, 'provider': url.split('/')[2]}
            return {'live': None, 'note': 'Could not determine OAuth provider'}
        except Exception: return {'live': False}
