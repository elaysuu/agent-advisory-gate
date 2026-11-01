'use strict';
// Gumroad license verification.
// Docs (checked 2026-11-01): https://gumroad.com/help/article/76-license-keys
//   POST https://api.gumroad.com/v2/licenses/verify, no OAuth needed.
//   Params: product_id (required for products created on/after 2023-01-09), license_key,
//           increment_uses_count ("true"/"false", optional, default "true").
//   Response: { success, uses, purchase: { refunded, disputed, chargebacked,
//           subscription_ended_at, subscription_cancelled_at, subscription_failed_at, ... } }
//   "If one of these fields is not null, you can disable the license and terminate access."
//   Invalid key => 404 with { success:false, message }.
const GUMROAD_VERIFY_URL = 'https://api.gumroad.com/v2/licenses/verify';
// TODO(after Gumroad product exists): replace with the product_id from the License key block.
const GUMROAD_PRODUCT_ID = 'REPLACE_WITH_GUMROAD_PRODUCT_ID';

async function verifyLicense(key, { fetchImpl = fetch, productId = GUMROAD_PRODUCT_ID, timeoutMs = 8000 } = {}) {
  if (!key) return { tier: 'free', reason: 'no license-key input' };
  if (productId.startsWith('REPLACE_')) return { tier: 'free', reason: 'product_id not configured in this build' };
  const body = new URLSearchParams({ product_id: productId, license_key: key, increment_uses_count: 'false' });
  let res, json;
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    res = await fetchImpl(GUMROAD_VERIFY_URL, { method: 'POST', body, signal: ctl.signal,
      headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    clearTimeout(t);
    json = await res.json();
  } catch (e) {
    // Fail OPEN to free tier: never break the user's build because of licensing.
    return { tier: 'free', reason: `license server unreachable (${e.name || 'error'}); running free tier` };
  }
  if (res.status >= 500) return { tier: 'free', reason: `license server error ${res.status}; running free tier` };
  if (!json || !json.success) return { tier: 'free', reason: 'license key not valid for this product' };
  const p = json.purchase || {};
  for (const f of ['subscription_cancelled_at', 'subscription_ended_at', 'subscription_failed_at']) {
    if (p[f]) return { tier: 'free', reason: `membership inactive (${f})` };
  }
  if (p.refunded || p.chargebacked || p.disputed) return { tier: 'free', reason: 'purchase refunded/disputed' };
  return { tier: 'pro', reason: 'license valid' };
}

module.exports = { verifyLicense, GUMROAD_PRODUCT_ID, GUMROAD_VERIFY_URL };
