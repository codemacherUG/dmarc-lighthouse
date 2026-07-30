/** Suggest a short account name — prefer the email domain, else a cleaned IMAP host. */
export function suggestAccountName(user: string, host: string): string {
  const email = user.trim().toLowerCase()
  const at = email.lastIndexOf('@')
  if (at > 0 && at < email.length - 1) {
    const domain = email.slice(at + 1).replace(/\.$/, '')
    if (domain) return domain
  }

  let cleaned = host.trim().toLowerCase().replace(/\.$/, '')
  cleaned = cleaned.replace(/^(imap|mail|smtp|mx|pop|pop3)\./, '')
  return cleaned || email || 'IMAP'
}

/** Display label: custom name if set, otherwise the domain suggestion. */
export function resolveAccountLabel(account: {
  name?: string | null
  user: string
  host: string
}): string {
  const custom = account.name?.trim()
  if (custom) return custom
  return suggestAccountName(account.user, account.host)
}
