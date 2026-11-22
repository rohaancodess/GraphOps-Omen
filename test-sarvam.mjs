import fs from 'fs';
import { SarvamAIClient } from 'sarvamai';

// Load .env if not loaded via --env-file
if (!process.env.SARVAM_API_KEY && fs.existsSync('.env')) {
  const envContent = fs.readFileSync('.env', 'utf8');
  for (const line of envContent.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const idx = trimmed.indexOf('=');
      if (idx !== -1) {
        process.env[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
      }
    }
  }
}

const client = new SarvamAIClient({
  apiSubscriptionKey: process.env.SARVAM_API_KEY,
});

async function main() {
  const response = await client.chat.completionsV2({
    model: 'glm5.3-flash',
    messages: [
      {
        role: 'user',
        content: 'Explain in one sentence why you are fast and efficient.',
      },
    ],
  });

  const reply = response.choices?.[0]?.message?.content;
  const reasoning = response.choices?.[0]?.message?.reasoning_content;

  console.log('--- Reply ---');
  console.log(reply);
  if (reasoning) {
    console.log('\n--- Reasoning ---');
    console.log(reasoning);
  }
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
