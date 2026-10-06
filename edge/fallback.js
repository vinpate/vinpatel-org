const STYLE = `
:root{--paper:#EFEFEA;--ink:#232722;--moss:#4C6A4F;--stone:#646860;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--paper:#1C201B;--ink:#E6E7E1;--moss:#9BBE9C;--stone:#91958C}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;min-height:100svh;display:flex;flex-direction:column;justify-content:center;padding:3rem 1.75rem;background:var(--paper);color:var(--ink);font:1.0625rem/1.65 ui-serif,"Iowan Old Style","Palatino Linotype",Charter,Georgia,serif}
main{width:100%;max-width:34rem;margin-inline:auto}
h1{display:inline-block;margin:0;padding-bottom:.75rem;border-bottom:2px solid var(--moss);font:500 clamp(1.75rem,7vw,2.75rem)/1.1 ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;letter-spacing:-.02em}
.name{margin:2.25rem 0 0;font-weight:600}
.title{margin:0 0 2rem;color:var(--stone)}
dl{display:grid;grid-template-columns:5.5rem 1fr;gap:.55rem 1.25rem;margin:0 0 2.5rem;font:.875rem/1.65 ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace}
dt{color:var(--stone);font-size:.8125rem}
dd{margin:0;overflow-wrap:anywhere}
a{color:inherit;text-decoration-color:var(--moss);text-underline-offset:.2em}
a:focus-visible{outline:2px solid var(--moss);outline-offset:3px;border-radius:2px}
.notice{margin:0;font-size:.9375rem;font-style:italic;color:var(--stone)}
@media (max-width:34rem){body{padding:2rem 1.25rem}dl{grid-template-columns:1fr;gap:.15rem}dd{margin-bottom:.9rem}}
`;

const STYLE_HASH = "sha256-U6DZfbeBHhV8gMRmp44VS+Km04c+p1HgKgB8Iu4uEzY=";

const CARD = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Vin Patel</title>
<style>${STYLE}</style>
</head>
<body>
<main>
<h1>vinpatel.org</h1>
<p class="name">Vin Patel</p>
<p class="title"><a href="https://nirvanalabs.io">Co-founding engineer, Nirvana Labs</a></p>
<dl>
<dt>mail</dt><dd><a href="mailto:mail@vinpatel.org">mail@vinpatel.org</a></dd>
<dt>github</dt><dd><a href="https://github.com/vinpate" rel="me">github.com/vinpate</a></dd>
<dt>linkedin</dt><dd><a href="https://www.linkedin.com/in/vin-pate" rel="me">linkedin.com/in/vin-pate</a></dd>
<dt>bluesky</dt><dd><a href="https://bsky.app/profile/vinfa.bsky.social" rel="me">bsky.app/profile/vinfa.bsky.social</a></dd>
<dt>photos</dt><dd><a href="https://www.instagram.com/vinfral7" rel="me">instagram.com/vinfral7</a></dd>
</dl>
<p class="notice">The origin behind this page is offline right now. Mail still works.</p>
</main>
</body>
</html>
`;

const HEADERS = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "Retry-After": "300",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "Content-Security-Policy": `default-src 'none'; style-src '${STYLE_HASH}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
};

export default {
  async fetch(request) {
    try {
      const response = await fetch(request);
      if (response.status < 500) {
        return response;
      }
      await response.body?.cancel();
    } catch {
      // Unreachable origin: fall through to the card.
    }
    return new Response(request.method === "HEAD" ? null : CARD, { status: 503, headers: HEADERS });
  },
};
