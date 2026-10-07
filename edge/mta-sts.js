// Serves the MTA-STS policy for the zone from the POLICY binding, which
// Terraform builds from infra/mail.tf. It never talks to an origin, so the
// policy stays fetchable while the site is down.
const PATH = "/.well-known/mta-sts.txt";

const TEXT = {
  "Content-Type": "text/plain; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
};

export default {
  fetch(request, env) {
    if (new URL(request.url).pathname !== PATH) {
      return new Response("not found\n", { status: 404, headers: { ...TEXT, "Cache-Control": "no-store" } });
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed\n", {
        status: 405,
        headers: { ...TEXT, Allow: "GET, HEAD", "Cache-Control": "no-store" },
      });
    }
    return new Response(request.method === "HEAD" ? null : env.POLICY, {
      status: 200,
      headers: { ...TEXT, "Cache-Control": "public, max-age=300" },
    });
  },
};
