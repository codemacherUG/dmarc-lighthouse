/**
 * Naming the sending service is more actionable than naming the network:
 * "SendGrid" tells an admin what to check, "AS396982 Google LLC" does not.
 */
export type SenderKind =
  /** Bulk / transactional mail provider. */
  | 'esp'
  /** Hosted mailbox provider (also sends user mail). */
  | 'mailbox'
  /** CRM, ticketing, marketing suite. */
  | 'saas'
  /** Mail security gateway / relay. */
  | 'gateway'
  /** Hosting or cloud platform without a specific mail product. */
  | 'infra'

export interface KnownSender {
  name: string
  kind: SenderKind
}

interface SenderPattern extends KnownSender {
  /** Matched against the PTR hostname and the AS organization. */
  pattern: RegExp
}

/**
 * Ordered most specific first: a Microsoft 365 protection host must win over the
 * generic Microsoft entry, and SES over the AWS network it lives in.
 */
const SENDER_PATTERNS: SenderPattern[] = [
  { name: 'Microsoft 365', kind: 'mailbox', pattern: /\bprotection\.outlook\.com\b/i },
  { name: 'Microsoft 365', kind: 'mailbox', pattern: /\b(outlook|office365|exchangelabs)\b/i },
  { name: 'Google Workspace', kind: 'mailbox', pattern: /\bgoogle(mail)?\.com\b|\bgmail\b/i },
  { name: 'Amazon SES', kind: 'esp', pattern: /\bamazonses\b|\bemail-smtp\b/i },
  { name: 'SendGrid', kind: 'esp', pattern: /\bsendgrid\b/i },
  { name: 'Mailchimp', kind: 'esp', pattern: /\b(mailchimp|mcsv|rsgsv|mandrillapp)\b/i },
  { name: 'Mailgun', kind: 'esp', pattern: /\bmailgun\b/i },
  { name: 'Postmark', kind: 'esp', pattern: /\bpostmarkapp\b/i },
  { name: 'SparkPost', kind: 'esp', pattern: /\bsparkpost(mail)?\b/i },
  { name: 'Brevo', kind: 'esp', pattern: /\b(brevo|sendinblue)\b/i },
  { name: 'Mailjet', kind: 'esp', pattern: /\bmailjet\b/i },
  { name: 'Klaviyo', kind: 'esp', pattern: /\bklaviyo\b/i },
  { name: 'ActiveCampaign', kind: 'esp', pattern: /\bactivecampaign\b|\bacemsv\b/i },
  { name: 'CleverReach', kind: 'esp', pattern: /\bcleverreach\b/i },
  { name: 'Rapidmail', kind: 'esp', pattern: /\brapidmail\b/i },
  { name: 'Inxmail', kind: 'esp', pattern: /\binxmail\b/i },
  {
    name: 'Salesforce',
    kind: 'saas',
    pattern: /\b(salesforce|exacttarget|pardot|et[._-]?smtp)\b/i
  },
  { name: 'HubSpot', kind: 'saas', pattern: /\bhubspot(email)?\b/i },
  { name: 'Zendesk', kind: 'saas', pattern: /\bzendesk\b/i },
  { name: 'Atlassian', kind: 'saas', pattern: /\batlassian\b/i },
  { name: 'Freshworks', kind: 'saas', pattern: /\bfreshdesk|freshemail\b/i },
  { name: 'DocuSign', kind: 'saas', pattern: /\bdocusign\b/i },
  { name: 'Intuit', kind: 'saas', pattern: /\bintuit\b/i },
  { name: 'Shopify', kind: 'saas', pattern: /\bshopify(email)?\b/i },
  { name: 'Zoho', kind: 'mailbox', pattern: /\bzoho\b/i },
  { name: 'Proton Mail', kind: 'mailbox', pattern: /\bproton(mail)?\b/i },
  { name: 'Yahoo', kind: 'mailbox', pattern: /\byahoo\b/i },
  { name: 'GMX', kind: 'mailbox', pattern: /\bgmx\b/i },
  { name: 'Web.de', kind: 'mailbox', pattern: /\bweb\.de\b/i },
  { name: 'Mailbox.org', kind: 'mailbox', pattern: /\bmailbox\.org\b/i },
  { name: 'Posteo', kind: 'mailbox', pattern: /\bposteo\b/i },
  { name: 'Fastmail', kind: 'mailbox', pattern: /\b(fastmail|messagingengine)\b/i },
  { name: 'Proofpoint', kind: 'gateway', pattern: /\b(pphosted|proofpoint)\b/i },
  { name: 'Mimecast', kind: 'gateway', pattern: /\bmimecast\b/i },
  { name: 'Barracuda', kind: 'gateway', pattern: /\b(barracuda|barracudanetworks)\b/i },
  { name: 'Hornetsecurity', kind: 'gateway', pattern: /\b(hornetsecurity|antispameurope)\b/i },
  { name: 'Retarus', kind: 'gateway', pattern: /\bretarus\b/i },
  { name: 'NoSpamProxy', kind: 'gateway', pattern: /\bnospamproxy\b/i },
  { name: 'Cloudflare', kind: 'infra', pattern: /\bcloudflare\b/i },
  { name: 'AWS', kind: 'infra', pattern: /\b(amazonaws|amazon\.com|aws)\b/i },
  { name: 'Azure', kind: 'infra', pattern: /\b(azure|microsoft)\b/i },
  { name: 'Google Cloud', kind: 'infra', pattern: /\b(googleusercontent|google cloud|1e100)\b/i },
  // AS orgs are plain names ("Google LLC"), so keep a loose fallback after the products.
  { name: 'Google', kind: 'infra', pattern: /\bgoogle\b/i },
  { name: 'Hetzner', kind: 'infra', pattern: /\bhetzner\b/i },
  { name: 'IONOS', kind: 'infra', pattern: /\b(ionos|1und1|1and1|united-internet)\b/i },
  { name: 'Strato', kind: 'infra', pattern: /\bstrato\b/i },
  { name: 'OVH', kind: 'infra', pattern: /\bovh\b/i },
  { name: 'DigitalOcean', kind: 'infra', pattern: /\bdigitalocean\b/i },
  { name: 'Linode', kind: 'infra', pattern: /\b(linode|akamai)\b/i },
  { name: 'Contabo', kind: 'infra', pattern: /\bcontabo\b/i },
  { name: 'netcup', kind: 'infra', pattern: /\bnetcup\b/i },
  { name: 'Mittwald', kind: 'infra', pattern: /\bmittwald\b/i },
  { name: 'Host Europe', kind: 'infra', pattern: /\bhosteurope\b/i },
  { name: 'DomainFactory', kind: 'infra', pattern: /\bdomainfactory\b/i },
  { name: 'Telekom', kind: 'infra', pattern: /\b(t-online|deutsche telekom|telekom)\b/i }
]

/**
 * Identify the sending service from reverse DNS and the AS organization.
 * PTR wins over the AS org, because an ESP hosted inside AWS still names itself
 * in reverse DNS while the ASN only shows the cloud.
 */
export function identifySender(input: {
  ptr?: string | null
  asOrg?: string | null
}): KnownSender | null {
  const ptr = (input.ptr ?? '').trim()
  const asOrg = (input.asOrg ?? '').trim()
  for (const source of [ptr, asOrg]) {
    if (!source) continue
    for (const entry of SENDER_PATTERNS) {
      if (entry.pattern.test(source)) return { name: entry.name, kind: entry.kind }
    }
  }
  return null
}

/** Identify a service from an SPF `include:` token, e.g. `sendgrid.net` → SendGrid. */
export function identifySenderFromSpfInclude(include: string): KnownSender | null {
  return identifySender({ ptr: include })
}
