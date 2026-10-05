// Meu Fiado - servidor de licencas (Cloudflare Worker + D1)
const J = (o, s = 200) =>
  new Response(JSON.stringify(o), {
    status: s,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
const AB = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const newKey = () => {
  const c = [...crypto.getRandomValues(new Uint8Array(12))]
    .map((x) => AB[x % 32])
    .join("");
  return `MF-${c.slice(0, 4)}-${c.slice(4, 8)}-${c.slice(8)}`;
};
const eq = (a, b) => {
  a = String(a);
  b = String(b);
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++)
    d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
};
// limite de tentativas erradas: 10 a cada 15 minutos por IP
async function limited(env, ip, add) {
  const n = Date.now(),
    w = n - 9e5;
  await env.DB.prepare("DELETE FROM fails WHERE t<?").bind(w).run();
  if (add)
    await env.DB.prepare("INSERT INTO fails(ip,t) VALUES(?,?)")
      .bind(ip, n)
      .run();
  return (
    (
      await env.DB.prepare("SELECT COUNT(*) c FROM fails WHERE ip=? AND t>?")
        .bind(ip, w)
        .first()
    ).c >= 10
  );
}
async function lic(env, req, b, bind) {
  const k = String(b.key || "")
      .trim()
      .toUpperCase(),
    d = String(b.device || "").slice(0, 64),
    ip = req.headers.get("cf-connecting-ip") || "x";
  if (!k || !d) return J({ ok: false, error: "invalid" }, 400);
  if (await limited(env, ip, false))
    return J({ ok: false, error: "rate" }, 429);
  const get = () =>
      env.DB.prepare("SELECT * FROM licenses WHERE key=?").bind(k).first(),
    L = await get();
  if (!L) {
    await limited(env, ip, true);
    return J({ ok: false, error: "invalid" }, 404);
  }
  if (L.status !== "active") return J({ ok: false, error: "blocked" }, 403);
  if (!L.device) {
    if (!bind) return J({ ok: false, error: "invalid" }, 403);
    await env.DB.prepare(
      "UPDATE licenses SET device=?,activated=? WHERE key=? AND device IS NULL"
    )
      .bind(d, Date.now(), k)
      .run();
    if ((await get()).device !== d)
      return J({ ok: false, error: "other_device" }, 409);
  } else if (L.device !== d)
    return J({ ok: false, error: "other_device" }, 409);
  await env.DB.prepare("UPDATE licenses SET seen=? WHERE key=?")
    .bind(Date.now(), k)
    .run();
  return J({ ok: true });
}
async function admin(env, req, u) {
  const ip = "a:" + (req.headers.get("cf-connecting-ip") || "x");
  if (await limited(env, ip, false)) return J({ error: "rate" }, 429);
  if (
    !env.ADMIN_TOKEN ||
    !eq(
      (req.headers.get("authorization") || "").replace("Bearer ", ""),
      env.ADMIN_TOKEN
    )
  ) {
    await limited(env, ip, true);
    return J({ error: "unauthorized" }, 401);
  }
  const p = u.pathname;
  if (p == "/api/admin/list")
    return J({
      rows: (
        await env.DB.prepare(
          "SELECT key,status,buyer,device IS NOT NULL AS bound,created,activated,seen FROM licenses ORDER BY created DESC LIMIT 500"
        ).all()
      ).results,
    });
  const b = await req.json().catch(() => ({}));
  if (p == "/api/admin/create") {
    const n = Math.min(Math.max(+b.n || 1, 1), 50),
      ks = [];
    for (let i = 0; i < n; i++) {
      const k = newKey();
      await env.DB.prepare(
        "INSERT INTO licenses(key,status,buyer,created) VALUES(?,?,?,?)"
      )
        .bind(k, "active", String(b.buyer || "").slice(0, 80), Date.now())
        .run();
      ks.push(k);
    }
    return J({ keys: ks });
  }
  if (p == "/api/admin/set") {
    const q = {
      block: "UPDATE licenses SET status='blocked' WHERE key=?",
      unblock: "UPDATE licenses SET status='active' WHERE key=?",
      reset: "UPDATE licenses SET device=NULL,activated=NULL WHERE key=?",
    }[b.action];
    if (!q) return J({ error: "bad" }, 400);
    await env.DB.prepare(q).bind(String(b.key)).run();
    return J({ ok: true });
  }
  return J({ error: "notfound" }, 404);
}
export default {
  async fetch(req, env) {
    const u = new URL(req.url),
      p = u.pathname;
    if (p.startsWith("/api/admin/")) return admin(env, req, u);
    if (req.method == "POST" && (p == "/api/activate" || p == "/api/check"))
      return lic(
        env,
        req,
        await req.json().catch(() => ({})),
        p == "/api/activate"
      );
    if (p.startsWith("/api/")) return J({ error: "notfound" }, 404);
    return env.ASSETS.fetch(req);
  },
};
