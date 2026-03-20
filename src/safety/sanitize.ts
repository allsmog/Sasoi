/**
 * Sanitizes attacker-controlled values before interpolating into LLM prompts.
 * Prevents prompt injection via newlines, non-printable chars, and excessive length.
 */
export function sanitizeForPrompt(value: string | undefined | null, maxLength = 200): string {
  if (value == null) return 'unknown'
  return value
    // Replace newlines and tabs with spaces (preserve word boundaries)
    .replace(/[\r\n\t]/g, ' ')
    // Strip remaining non-printable and control characters (keep space and printable ASCII)
    .replace(/[^\x20-\x7E]/g, '')
    // Collapse whitespace
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength)
}
