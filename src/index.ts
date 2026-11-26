export interface Env {
  TOKENS: DurableObjectNamespace;
  TODOIST_APP_CLIENT_ID: string;
  TODOIST_APP_CLIENT_SECRET: string;
  TARGET_PROJECT_ID: string;
}

const API = "https://api.todoist.com/api/v1";
const TOKEN_URL = "https://api.todoist.com/oauth/access_token";
const EVENTS = ["item:added", "item:updated"];
const enc = new TextEncoder();

const b64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function hmacKey(secret: string, usage: "sign" | "verify") {
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [usage]);
}

async function validSignature(env: Env, body: string, sig: string | null): Promise<boolean> {
  try {
    return !!sig && (await crypto.subtle.verify("HMAC", await hmacKey(env.TODOIST_APP_CLIENT_SECRET, "verify"), b64(sig), enc.encode(body)));
  } catch {
    return false; // malformed base64
  }
}

/** Task id to move into the target project, or null. Subtasks follow their parent. */
export function needsMove(payload: any, target: string): string | null {
  if (!EVENTS.includes(payload?.event_name)) return null;
  const t = payload.event_data ?? {};
  if (!t.id || t.parent_id || String(t.project_id) === target) return null;
  return String(t.id);
}

interface OAuth { access_token: string; refresh_token?: string; expires_at: number }

const toOAuth = (j: any, previousRefresh?: string): OAuth => ({
  access_token: j.access_token,
  refresh_token: j.refresh_token ?? previousRefresh,
  expires_at: Date.now() + j.expires_in * 1000,
});

/**
 * Single owner of the OAuth tokens. Todoist rotates the refresh token on every use and
 * revokes the whole grant if a consumed one is replayed, so storage must be strongly
 * consistent and refreshes must not run in parallel (hence a Durable Object, not KV).
 */
export class TokenStore {
  private refreshing?: Promise<string | null>;
  constructor(private state: DurableObjectState, private env: Env) {}

  /** PUT saves a token response; GET returns a currently valid access token or null. */
  async fetch(req: Request): Promise<Response> {
    if (req.method === "PUT") {
      await this.state.storage.put("oauth", toOAuth(await req.json()));
      return new Response(null, { status: 204 });
    }
    this.refreshing ??= this.accessToken().finally(() => (this.refreshing = undefined));
    return Response.json({ token: await this.refreshing });
  }

  private async accessToken(): Promise<string | null> {
    const saved = await this.state.storage.get<OAuth>("oauth");
    if (!saved) return null;
    if (Date.now() < saved.expires_at - 60_000) return saved.access_token;
    if (!saved.refresh_token) return null;
    const r = await fetch(TOKEN_URL, {
      method: "POST",
      body: new URLSearchParams({
        client_id: this.env.TODOIST_APP_CLIENT_ID,
        client_secret: this.env.TODOIST_APP_CLIENT_SECRET,
        grant_type: "refresh_token",
        refresh_token: saved.refresh_token,
      }),
    });
    const j: any = r.ok ? await r.json() : {};
    if (!j.access_token) {
      console.error("token refresh failed: open /oauth/start", r.status);
      return null;
    }
    await this.state.storage.put("oauth", toOAuth(j, saved.refresh_token));
    return j.access_token;
  }
}

const tokenStore = (env: Env) => env.TOKENS.get(env.TOKENS.idFromName("owner"));

async function getToken(env: Env): Promise<string | null> {
  const r = await tokenStore(env).fetch("https://tokens/");
  return ((await r.json()) as { token: string | null }).token;
}

async function move(env: Env, id: string) {
  const token = await getToken(env);
  if (!token) return console.error("no valid OAuth token: open /oauth/start");
  const r = await fetch(`${API}/tasks/${id}/move`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ project_id: env.TARGET_PROJECT_ID }),
  });
  if (r.ok) console.log("moved task", id);
  else console.error("move failed", id, r.status, (await r.text()).slice(0, 200));
}

// stateless CSRF: state = nonce.HMAC(nonce)
async function makeState(env: Env, nonce: string) {
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env.TODOIST_APP_CLIENT_SECRET, "sign"), enc.encode(nonce));
  return `${nonce}.${hex(sig)}`;
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/health") {
      return Response.json({ ok: true, authorized: !!(await getToken(env)) });
    }

    if (url.pathname === "/webhook" && req.method === "POST") {
      const body = await req.text();
      if (!(await validSignature(env, body, req.headers.get("X-Todoist-Hmac-SHA256")))) {
        return new Response("bad signature", { status: 401 });
      }
      let payload;
      try { payload = JSON.parse(body); } catch { return new Response("bad json", { status: 400 }); }
      const id = needsMove(payload, env.TARGET_PROJECT_ID);
      if (id) ctx.waitUntil(move(env, id));
      return Response.json({ ok: true });
    }

    if (url.pathname === "/oauth/start") {
      const nonce = crypto.randomUUID();
      const q = new URLSearchParams({ client_id: env.TODOIST_APP_CLIENT_ID, scope: "data:read_write", state: await makeState(env, nonce) });
      return Response.redirect(`https://app.todoist.com/oauth/authorize?${q}`, 302);
    }

    if (url.pathname === "/oauth/callback") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state") ?? "";
      if (!code || state !== (await makeState(env, state.split(".")[0]))) return new Response("bad state", { status: 400 });
      const r = await fetch(TOKEN_URL, {
        method: "POST",
        body: new URLSearchParams({ client_id: env.TODOIST_APP_CLIENT_ID, client_secret: env.TODOIST_APP_CLIENT_SECRET, code }),
      });
      const j: any = r.ok ? await r.json() : {};
      if (!j.access_token) {
        console.error("token exchange failed", r.status);
        return new Response("token exchange failed", { status: 502 });
      }
      await tokenStore(env).fetch("https://tokens/", { method: "PUT", body: JSON.stringify(j) });
      return new Response("<h3>Готово ✅ Можно закрыть вкладку.</h3>", { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    return new Response("not found", { status: 404 });
  },
};
