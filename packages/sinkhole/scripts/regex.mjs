/**
 * Regex - Semantic Version Pattern.
 *
 * Matches the release versions supported by the generated pfSense package.
 * Keeping the pattern shared prevents validation logic from mixing with I/O.
 *
 * @since 0.0.0
 */
export const semanticVersionPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

/**
 * Regex - Release Signing Key Pattern.
 *
 * Accepts OpenSSH Ed25519 public keys with an optional trailing comment.
 * Other key algorithms and malformed Ed25519 payloads fail validation.
 *
 * @since 1.0.0
 */
export const releaseSigningKeyPattern = /^ssh-ed25519\s+AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}(?:\s.*)?$/;

/**
 * Regex - Curl Call Pattern.
 *
 * Matches one PHP cURL function call such as "curl_exec(". Function names inside
 * strings and translation keys like "curl_support_unavailable" do not match.
 *
 * @since 1.3.3
 */
export const curlCallPattern = /\bcurl_[a-z_]+\s*\(/;

/**
 * Regex - Platform Configuration Call Pattern.
 *
 * Matches one direct pfSense configuration read, write, or save call, which only
 * the platform adapter may make.
 *
 * @since 1.3.3
 */
export const platformConfigurationCallPattern = /(?<![>\w])\\?(?:config_(?:get|set|del)_path|write_config)\s*\(/;
