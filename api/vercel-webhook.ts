import crypto from 'crypto';

// Vercel webhook event types
// Docs: https://vercel.com/docs/observability/webhooks-overview/webhooks-api
interface VercelWebhookEvent {
  id: string;
  type: string;
  payload: {
    deployment: {
      id: string;
      name: string;
      url: string;
      meta: Record<string, string>;
    };
    links: {
      deployment: string;
      project: string;
    };
    name: string;
    url: string;
  };
  createdAt: number;
}

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL;

export async function POST(req: Request): Promise<Response> {
  // Validate config
  if (!WEBHOOK_SECRET || !DISCORD_WEBHOOK_URL) {
    console.error('Missing WEBHOOK_SECRET or DISCORD_WEBHOOK_URL');
    return new Response('Server misconfigured', { status: 500 });
  }

  // Read raw body for signature verification
  const rawBody = await req.text();

  // Verify HMAC-SHA1 signature
  const signature = req.headers.get('x-vercel-signature');
  if (!signature) {
    return new Response('Missing signature', { status: 401 });
  }

  const expectedSig = crypto
    .createHmac('sha1', WEBHOOK_SECRET)
    .update(Buffer.from(rawBody, 'utf-8'))
    .digest('hex');

  if (signature !== expectedSig) {
    return new Response('Invalid signature', { status: 401 });
  }

  // Parse event
  const event: VercelWebhookEvent = JSON.parse(rawBody);

  // Only handle deployment terminal states
  if (
    event.type !== 'deployment.succeeded' &&
    event.type !== 'deployment.error' &&
    event.type !== 'deployment.canceled'
  ) {
    console.log(`Ignoring event: ${event.type}`);
    return new Response('OK', { status: 200 });
  }

  try {
    await sendToDiscord(event);
    return new Response('Notification sent', { status: 200 });
  } catch (err) {
    console.error('Failed to send Discord notification:', err);
    return new Response('Internal error', { status: 500 });
  }
}

async function sendToDiscord(event: VercelWebhookEvent) {
  const { deployment, links } = event.payload;
  const stateLabel = event.type.split('.')[1].toUpperCase();

  // Map Vercel state to Discord color
  const colors: Record<string, number> = {
    SUCCEEDED: 0x2ecc71,  // green
    ERROR: 0xe74c3c,      // red
    CANCELED: 0x95a5a6,   // grey
  };

  const gitBranch = deployment.meta['githubCommitRef'] || 'unknown';
  const gitSha = deployment.meta['githubCommitSha'] || '';
  const gitMsg = deployment.meta['githubCommitMessage'] || '';
  const gitOrg = deployment.meta['githubCommitOrg'] || '';
  const commitUrl = gitOrg && deployment.meta['githubCommitRepo'] && gitSha
    ? `https://github.com/${gitOrg}/${deployment.meta['githubCommitRepo']}/commit/${gitSha}`
    : '';

  const embed = {
    title: `${stateLabel === 'ERROR' ? '❌' : stateLabel === 'CANCELED' ? '⏹️' : '✅'} Deployment ${stateLabel}`,
    url: links.deployment,
    color: colors[stateLabel] || 0x95a5a6,
    fields: [
      { name: 'Project', value: `[${deployment.name}](${links.project})`, inline: true },
      { name: 'Branch', value: gitBranch, inline: true },
      { name: 'Commit', value: commitUrl ? `[\`${gitSha.slice(0, 7)}\`](${commitUrl})` : gitSha.slice(0, 7), inline: true },
    ],
    timestamp: new Date(event.createdAt).toISOString(),
  };

  if (gitMsg) {
    embed.fields.push({ name: 'Message', value: gitMsg.slice(0, 100), inline: false });
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
