import { getStore } from "@netlify/blobs";
import { createHmac, timingSafeEqual } from "node:crypto";

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

const secret = () => (process.env.EDIT_PASSWORD || "") + "|ironlog";
const sign = (exp) => createHmac("sha256", secret()).update(String(exp)).digest("hex");
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};
function validToken(t) {
  if (!t) return false;
  const [exp, sig] = t.split(".");
  if (!(Number(exp) > Date.now())) return false;
  return safeEq(sig || "", sign(exp));
}

export default async (req) => {
  if (!process.env.EDIT_PASSWORD) {
    return json({ error: "EDIT_PASSWORD is not set in Netlify environment variables" }, 500);
  }
  const store = getStore("ironlog");

  // Anyone can read (view-only)
  if (req.method === "GET") {
    const state = await store.get("state", { type: "json" });
    return json({ state: state || null });
  }

  // Login: password -> signed token
  if (req.method === "POST") {
    let b;
    try { b = await req.json(); } catch { return json({ error: "Bad request" }, 400); }
    if (!safeEq(b.password || "", process.env.EDIT_PASSWORD)) {
      await new Promise((r) => setTimeout(r, 800)); // slow down guessing
      return json({ error: "Wrong password" }, 401);
    }
    const exp = Date.now() + (b.keep ? 30 : 0.5) * 864e5;
    return json({ token: `${exp}.${sign(exp)}`, exp });
  }

  // Save: only with a valid token
  if (req.method === "PUT") {
    const auth = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
    if (!validToken(auth)) return json({ error: "unauthorized" }, 401);
    const text = await req.text();
    if (text.length > 900000) return json({ error: "too large" }, 413);
    let s;
    try { s = JSON.parse(text); } catch { return json({ error: "bad json" }, 400); }
    if (!s || !Array.isArray(s.plans) || !s.plans.length) return json({ error: "invalid data" }, 400);
    await store.setJSON("state", s);
    return json({ ok: true });
  }

  return json({ error: "method not allowed" }, 405);
};

export const config = { path: "/api/data" };
