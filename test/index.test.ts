import { describe, expect, it, vi } from "vitest";
import worker, { needsMove, TokenStore } from "../src/index";

const T = "target";
const creds = { TODOIST_APP_CLIENT_ID: "id", TODOIST_APP_CLIENT_SECRET: "secret", TARGET_PROJECT_ID: T };

/** Real TokenStore over an in-memory storage, wired like a Durable Object binding. */
function makeEnv(saved?: object) {
  const data = new Map<string, any>(saved ? [["oauth", saved]] : []);
  const state: any = { storage: { get: async (k: string) => data.get(k), put: async (k: string, v: any) => void data.set(k, v) } };
  const store = new TokenStore(state, creds as any);
  const env: any = { ...creds, TOKENS: { idFromName: () => "id", get: () => ({ fetch: (u: string, i?: RequestInit) => store.fetch(new Request(u, i)) }) } };
  return { env, data };
}
const fresh = () => ({ access_token: "tok", refresh_token: "r1", expires_at: Date.now() + 3_600_000 });
const expired = () => ({ access_token: "old", refresh_token: "r1", expires_at: Date.now() - 1 });

const ev = (name = "item:added", extra: object = {}) => ({ event_name: name, event_data: { id: "1", project_id: "other", parent_id: null, ...extra } });

async function sign(body: string) {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode("secret"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(body)))));
}

async function post(payload: object, sig?: string, env = makeEnv(fresh()).env) {
  const body = JSON.stringify(payload);
  const waits: Promise<unknown>[] = [];
  const res = await worker.fetch(
    new Request("https://x/webhook", { method: "POST", body, headers: { "X-Todoist-Hmac-SHA256": sig ?? (await sign(body)) } }),
    env,
    { waitUntil: (p: Promise<unknown>) => waits.push(p) } as any,
  );
  await Promise.all(waits);
  return res;
}

describe("webhook", () => {
  it("rejects bad signature", async () => {
    expect((await post(ev(), "nope")).status).toBe(401);
  });

  it("decides what to move", () => {
    expect(needsMove(ev(), T)).toBe("1");
    expect(needsMove(ev("item:updated"), T)).toBe("1");
    expect(needsMove(ev("item:added", { project_id: T }), T)).toBeNull(); // already there
    expect(needsMove(ev("item:added", { parent_id: "9" }), T)).toBeNull(); // subtask
    expect(needsMove(ev("item:completed"), T)).toBeNull(); // other event
  });

  it("moves once via the Todoist API", async () => {
    const f = vi.fn(async () => new Response("{}"));
    vi.stubGlobal("fetch", f);
    expect((await post(ev())).status).toBe(200);
    expect((await post(ev("item:added", { project_id: T }))).status).toBe(200);
    expect(f).toHaveBeenCalledTimes(1);
    const [u, init] = f.mock.calls[0] as any;
    expect(u).toBe("https://api.todoist.com/api/v1/tasks/1/move");
    expect(JSON.parse(init.body)).toEqual({ project_id: T });
  });
});

describe("oauth", () => {
  it("callback rejects forged state; start redirects with signed state", async () => {
    const ctx: any = {};
    const { env, data } = makeEnv();
    expect((await worker.fetch(new Request("https://x/oauth/callback?code=c&state=bad.bad"), env, ctx)).status).toBe(400);
    const r = await worker.fetch(new Request("https://x/oauth/start"), env, ctx);
    const loc = new URL(r.headers.get("location")!);
    expect(loc.searchParams.get("client_id")).toBe("id");
    const state = loc.searchParams.get("state")!;
    vi.stubGlobal("fetch", async () => Response.json({ access_token: "newtok", refresh_token: "newref", expires_in: 3600 }));
    const ok = await worker.fetch(new Request(`https://x/oauth/callback?code=c&state=${state}`), env, ctx);
    expect(ok.status).toBe(200);
    expect(data.get("oauth")).toMatchObject({ access_token: "newtok", refresh_token: "newref" });
    expect(data.get("oauth").expires_at).toBeGreaterThan(Date.now() + 3_500_000);
  });
});

describe("token refresh", () => {
  const todoist = (refresh: () => Response) =>
    vi.fn(async (u: string, _init?: RequestInit) => (u.endsWith("/oauth/access_token") ? refresh() : new Response("{}")));

  it("refreshes an expired token once for concurrent webhooks and keeps the rotated refresh token", async () => {
    const f = todoist(() => Response.json({ access_token: "new", refresh_token: "r2", expires_in: 3600 }));
    vi.stubGlobal("fetch", f);
    const { env, data } = makeEnv(expired());
    await Promise.all([post(ev(), undefined, env), post(ev("item:added", { id: "2" }), undefined, env)]);
    const refreshes = f.mock.calls.filter(([u]) => u.endsWith("/oauth/access_token"));
    expect(refreshes).toHaveLength(1);
    expect(String(refreshes[0][1]!.body)).toContain("grant_type=refresh_token");
    const moves = f.mock.calls.filter(([u]) => u.endsWith("/move"));
    expect(moves.map(([, i]) => (i!.headers as any).Authorization)).toEqual(["Bearer new", "Bearer new"]);
    expect(data.get("oauth").refresh_token).toBe("r2");
  });

  it("reports unauthorized and does not move when refresh fails", async () => {
    const f = todoist(() => new Response("{}", { status: 400 }));
    vi.stubGlobal("fetch", f);
    const { env } = makeEnv(expired());
    await post(ev(), undefined, env);
    expect(f.mock.calls.filter(([u]) => u.endsWith("/move"))).toHaveLength(0);
    const h = await worker.fetch(new Request("https://x/health"), env, {} as any);
    expect(await h.json()).toMatchObject({ authorized: false });
  });
});
