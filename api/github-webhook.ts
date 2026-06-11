import crypto from 'crypto';

// GitHub webhook payload types (deployment_status event)
// Docs: https://docs.github.com/en/webhooks/webhook-events-and-payloads#deployment_status
interface DeploymentStatusEvent {
  action: string;
  deployment_status: {
    state: 'success' | 'failure' | 'error' | 'pending' | 'inactive';
    description: string | null;
    environment: string;
    environment_url: string | null;
    target_url: string | null;
    created_at: string;
    deployment: {
      sha: string;
      ref: string;
      task: string;
      environment: string;
      description: string | null;
      creator: { login: string };
    };
  };
  repository: {
    full_name: string;
    html_url: string;
  };
}

const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL;

export async function POST(req: Request): Promise<Response> {
  if (!GITHUB_WEBHOOK_SECRET || !DISCORD_WEBHOOK_URL) {
    console.error('Missing GITHUB_WEBHOOK_SECRET or DISCORD_WEBHOOK_URL');
    return new Response('Server misconfigured', { status: 500 });
  }

  // Verify event type
  const eventType = req.headers.get('x-github-event');
  if (eventType !== 'deployment_status') {
    console.log(`Ignoring event type: ${eventType}`);
    return new Response('OK', { status: 200 });
  }

  // Read raw body for signature verification
  const rawBody = await req.text();

  // Verify HMAC-SHA256 signature
  const signature = req.headers.get('x-hub-signature-256');
  if (!signature) {
    return new Response('Missing signature', { status: 401 });
  }

  const expectedSig = 'sha256=' +
    crypto
      .createHmac('sha256', GITHUB_WEBHOOK_SECRET)
      .update(Buffer.from(rawBody, 'utf-8'))
      .digest('hex');

  // Compare using timing-safe comparison
  const bufExpected = Buffer.from(expectedSig);
  const bufActual = Buffer.from(signature);
  if (bufExpected.length !== bufActual.length || !crypto.timingSafeEqual(bufExpected, bufActual)) {
    return new Response('Invalid signature', { status: 401 });
  }

  // Parse event
  const event: DeploymentStatusEvent = JSON.parse(rawBody);

  // Only handle terminal deployment states
  const state = event.deployment_status.state;
  if (state !== 'success' && state !== 'failure' && state !== 'error') {
    console.log(`Ignoring non-terminal state: ${state}`);
    return new Response('OK', { status: 200 });
  }

  try {
    await sendToDiscord(event);
    return new Response('Notification sent', { status: 200 });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const stack = err instanceof Error ? (err.stack || '') : '';
    console.error('Failed to send Discord notification:', msg, stack);
    return new Response(`Internal error: ${msg}`, { status: 500 });
  }
}

async function sendToDiscord(event: DeploymentStatusEvent) {
  const { deployment_status, repository } = event;
  const state = deployment_status.state;

  // Map state to Discord color
  const colors: Record<string, number> = {
    success: 0x2ecc71,  // green
    failure: 0xe74c3c,  // red
    error: 0xe74c3c,    // red
  };

  const deployUrl = deployment_status.target_url || deployment_status.environment_url || repository.html_url;
  const sha = deployment_status.deployment.sha;
  const branch = deployment_status.deployment.ref;
  const env = deployment_status.environment;
  const description = deployment_status.description || deployment_status.deployment.description || '';

  const emoji = state === 'success' ? '✅' : '❌';
  const deployLink = deployUrl ? `[View Deployment](${deployUrl})` : '';

  const embed = {
    title: `${emoji} Deploy ${state === 'success' ? 'Succeeded' : 'Failed'}`,
    url: deployUrl || undefined,
    color: colors[state] || 0x95a5a6,
    fields: [
      { name: 'Repository', value: `[${repository.full_name}](${repository.html_url})`, inline: true },
      { name: 'Environment', value: env, inline: true },
      { name: 'Branch', value: branch, inline: true },
      { name: 'Commit', value: `[\`${sha.slice(0, 7)}\`](${repository.html_url}/commit/${sha})`, inline: true },
    ],
    timestamp: new Date(deployment_status.created_at).toISOString(),
  };

  if (description) {
    embed.fields.push({ name: 'Description', value: description.slice(0, 200), inline: false });
  }

  const res = await fetch(DISCORD_WEBHOOK_URL!, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ embeds: [embed] }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Discord returned ${res.status}: ${text}`);
  }
}