const RANGE_ENDPOINT = "https://api.pwnedpasswords.com/range/";

export async function sha1Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0")
  )
    .join("")
    .toUpperCase();
}

export function findOccurrenceCount(responseBody, wantedSuffix) {
  for (const line of responseBody.split(/\r?\n/)) {
    const separator = line.indexOf(":");
    if (separator === -1) {
      continue;
    }

    const suffix = line.slice(0, separator).toUpperCase();
    if (suffix !== wantedSuffix) {
      continue;
    }

    const count = Number.parseInt(line.slice(separator + 1), 10);
    return Number.isFinite(count) ? count : 0;
  }
  return 0;
}

export async function checkPwnedPassword(
  password,
  {
    timeoutMs = 1_000,
    signal,
    fetchImpl = globalThis.fetch,
    hashPassword = sha1Hex,
  } = {}
) {
  const controller = new AbortController();
  let timedOut = false;

  const cancel = () => controller.abort(signal?.reason);
  if (signal?.aborted) {
    return { status: "cancelled" };
  }
  signal?.addEventListener("abort", cancel, { once: true });

  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  try {
    const hash = (await hashPassword(password)).toUpperCase();
    if (!/^[0-9A-F]{40}$/.test(hash)) {
      throw new Error("Password hash must be a 40-character SHA-1 value");
    }
    if (controller.signal.aborted) {
      return { status: timedOut ? "timeout" : "cancelled" };
    }

    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const response = await fetchImpl(RANGE_ENDPOINT + prefix, {
      method: "GET",
      headers: { "Add-Padding": "true" },
      credentials: "omit",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`Pwned Passwords returned HTTP ${response.status}`);
    }

    const occurrences = findOccurrenceCount(await response.text(), suffix);
    return occurrences > 0
      ? { status: "pwned", occurrences }
      : { status: "not-pwned" };
  } catch (error) {
    if (controller.signal.aborted) {
      return { status: timedOut ? "timeout" : "cancelled" };
    }
    return { status: "unavailable" };
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", cancel);
  }
}
