import { describe, expect, it, vi } from "vitest";
import worker, { needsMove } from "../src/index";

const T = "target";
const env: any = {
  KV: { get: async () => "tok", put: vi.fn() },
  TODOIST_APP_CLIENT_ID: "id",
  TODOIST_APP_CLIENT_SECRET: "secret",
  TARGET_PROJECT_ID: T,
};
const ev = (name = "item:added", extra: object = {}) => ({ event_name: name, event_data: { id: "1", project_id: "other", parent_id: null, ...extra } });

async function sign(body: string) {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode("secret"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(body)))));
}

async function post(payload: object, sig?: string) {
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
    expect((await worker.fetch(new Request("https://x/oauth/callback?code=c&state=bad.bad"), env, ctx)).status).toBe(400);
    const r = await worker.fetch(new Request("https://x/oauth/start"), env, ctx);
    const loc = new URL(r.headers.get("location")!);
    expect(loc.searchParams.get("client_id")).toBe("id");
    const state = loc.searchParams.get("state")!;
    vi.stubGlobal("fetch", async () => Response.json({ access_token: "newtok" }));
    const ok = await worker.fetch(new Request(`https://x/oauth/callback?code=c&state=${state}`), env, ctx);
    expect(ok.status).toBe(200);
    expect(env.KV.put).toHaveBeenCalledWith("access_token", "newtok");
  });
});
