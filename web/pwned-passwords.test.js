import assert from "node:assert/strict";
import test from "node:test";

import {
  checkPwnedPassword,
  findOccurrenceCount,
  sha1Hex,
} from "./pwned-passwords.js";

const hash = "ABCDE11111111111111111111111111111111111";

test("sha1Hex hashes UTF-8 input", async () => {
  assert.equal(
    await sha1Hex("password"),
    "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
  );
});

test("findOccurrenceCount handles CRLF data and padded zero-count rows", () => {
  const body = [
    "00000000000000000000000000000000000:0",
    "11111111111111111111111111111111111:42",
  ].join("\r\n");

  assert.equal(
    findOccurrenceCount(body, "11111111111111111111111111111111111"),
    42
  );
  assert.equal(
    findOccurrenceCount(body, "00000000000000000000000000000000000"),
    0
  );
});

test("checkPwnedPassword sends only the five-character prefix", async () => {
  let requestedURL;
  let requestOptions;
  const result = await checkPwnedPassword("secret", {
    hashPassword: async () => hash,
    fetchImpl: async (url, options) => {
      requestedURL = url;
      requestOptions = options;
      return {
        ok: true,
        text: async () => "11111111111111111111111111111111111:27\r\n",
      };
    },
  });

  assert.equal(requestedURL, "https://api.pwnedpasswords.com/range/ABCDE");
  assert.equal(requestOptions.headers["Add-Padding"], "true");
  assert.equal(requestOptions.credentials, "omit");
  assert.deepEqual(result, { status: "pwned", occurrences: 27 });
});

test("checkPwnedPassword reports a missing suffix", async () => {
  const result = await checkPwnedPassword("secret", {
    hashPassword: async () => hash,
    fetchImpl: async () => ({
      ok: true,
      text: async () => "22222222222222222222222222222222222:12\r\n",
    }),
  });

  assert.deepEqual(result, { status: "not-pwned" });
});

test("checkPwnedPassword distinguishes timeout and service failure", async (t) => {
  await t.test("timeout", async () => {
    const result = await checkPwnedPassword("secret", {
      timeoutMs: 5,
      hashPassword: async () => hash,
      fetchImpl: async (_url, { signal }) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener(
            "abort",
            () => reject(new DOMException("Aborted", "AbortError")),
            { once: true }
          );
        }),
    });

    assert.deepEqual(result, { status: "timeout" });
  });

  await t.test("service failure", async () => {
    const result = await checkPwnedPassword("secret", {
      hashPassword: async () => hash,
      fetchImpl: async () => ({ ok: false, status: 503 }),
    });

    assert.deepEqual(result, { status: "unavailable" });
  });
});

test("checkPwnedPassword can be cancelled by its caller", async () => {
  const controller = new AbortController();
  controller.abort();

  const result = await checkPwnedPassword("secret", {
    signal: controller.signal,
    hashPassword: async () => hash,
  });

  assert.deepEqual(result, { status: "cancelled" });
});
