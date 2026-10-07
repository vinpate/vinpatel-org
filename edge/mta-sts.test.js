import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "./mta-sts.js";

const POLICY =
  "version: STSv1\r\nmode: testing\r\nmx: mx01.mail.icloud.com\r\nmx: mx02.mail.icloud.com\r\nmax_age: 604800\r\n";
const env = { POLICY };
const ask = (path, method = "GET") =>
  worker.fetch(new Request(`https://mta-sts.vinpatel.org${path}`, { method }), env);

test("serves the bound policy at the well-known path", async () => {
  const response = await ask("/.well-known/mta-sts.txt");
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "text/plain; charset=utf-8");
  assert.equal(response.headers.get("cache-control"), "public, max-age=300");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(await response.text(), POLICY);
});

test("HEAD gets the headers and no body", async () => {
  const response = await ask("/.well-known/mta-sts.txt", "HEAD");
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "");
});

test("every other path is not found", async () => {
  for (const path of ["/", "/.well-known/", "/.well-known/mta-sts.txt/", "/mta-sts.txt", "/.well-known/mta-sts.txt?x=1"]) {
    const response = await ask(path);
    assert.equal(response.status, path.includes("?") ? 200 : 404, path);
  }
});

test("other methods are refused with Allow", async () => {
  for (const method of ["POST", "PUT", "DELETE", "OPTIONS"]) {
    const response = await ask("/.well-known/mta-sts.txt", method);
    assert.equal(response.status, 405, method);
    assert.equal(response.headers.get("allow"), "GET, HEAD");
  }
});

test("never calls an origin", async () => {
  globalThis.fetch = () => {
    throw new Error("origin called");
  };
  const response = await ask("/.well-known/mta-sts.txt");
  assert.equal(response.status, 200);
});
