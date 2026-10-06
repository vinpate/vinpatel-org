import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import worker from "./fallback.js";

let upstream;

beforeEach(() => {
  globalThis.fetch = async (request) => upstream(request);
});

const visit = (method = "GET") => worker.fetch(new Request("https://vinpatel.org/", { method }));

test("returns origin responses below 500 untouched", async () => {
  for (const status of [200, 301, 304, 404, 405]) {
    const origin = new Response(null, { status });
    upstream = () => origin;
    assert.equal(await visit(), origin, `status ${status}`);
  }
});

test("serves the card when the origin answers 5xx", async () => {
  for (const status of [500, 502, 503, 530]) {
    upstream = () => new Response("tunnel error", { status });
    const response = await visit();
    assert.equal(response.status, 503, `origin status ${status}`);
    assert.match(await response.text(), /mail@vinpatel\.org/);
  }
});

test("serves the card when the origin is unreachable", async () => {
  upstream = () => {
    throw new TypeError("fetch failed");
  };
  const response = await visit();
  assert.equal(response.status, 503);
  assert.match(await response.text(), /origin behind this page is offline/);
});

test("card carries cache and security headers", async () => {
  upstream = () => new Response(null, { status: 530 });
  const response = await visit();
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("retry-after"), "300");
  for (const name of [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
  ]) {
    assert.ok(response.headers.get(name), `missing ${name}`);
  }
});

test("HEAD and POST get the card's status, HEAD without a body", async () => {
  upstream = () => new Response(null, { status: 530 });
  const head = await visit("HEAD");
  assert.equal(head.status, 503);
  assert.equal(await head.text(), "");
  const post = await visit("POST");
  assert.equal(post.status, 503);
});

test("CSP allows exactly the card's inline stylesheet", async () => {
  upstream = () => new Response(null, { status: 530 });
  const response = await visit();
  const html = await response.text();
  const style = html.slice(html.indexOf("<style>") + "<style>".length, html.indexOf("</style>"));
  const hash = `sha256-${createHash("sha256").update(style).digest("base64")}`;
  const csp = response.headers.get("content-security-policy");
  assert.ok(csp.includes(`style-src '${hash}'`), `CSP must allow '${hash}', got: ${csp}`);
});
