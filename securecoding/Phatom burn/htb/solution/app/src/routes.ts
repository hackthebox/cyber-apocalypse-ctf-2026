import express from "express";
import fs from "node:fs";
import path from "node:path";
import type { AppConfig } from "./config.js";
import { recentShardFilings } from "./chain.js";
import {
  consumeUnlockReceipt,
  issueArchiveToken,
  verifyArchiveToken,
  verifyUnlockReceipt,
  type UnlockReceipt
} from "./sourceVault.js";
import {
  authenticate, issueSession, readSession, sessionCookie,
  SESSION_COOKIE, type Session
} from "./auth.js";
import {
  appShell, loginPage, overviewPage, shardsPage,
  sourcePage, operationsPage, statusPage
} from "./web.js";

export function routes(config: AppConfig) {
  const router = express.Router();

  // Console pages sit behind an operator login; the programmatic /api and
  // /archive relay surfaces are reached by the runtime, not the browser.
  function requireOperator(req: express.Request, res: express.Response, next: express.NextFunction) {
    const session = readSession(config, req);
    if (!session) {
      res.redirect(302, "/app/login");
      return;
    }
    (req as express.Request & { session: Session }).session = session;
    next();
  }

  function sessionOf(req: express.Request): Session {
    return (req as express.Request & { session: Session }).session;
  }

  router.get("/login", (req, res) => {
    if (readSession(config, req)) {
      res.redirect(302, "/app/");
      return;
    }
    res.type("html").send(loginPage(config));
  });

  router.post("/login", express.urlencoded({ extended: false }), async (req, res) => {
    const username = String(req.body.username ?? "").trim();
    const password = String(req.body.password ?? "");
    if (!username || !password) {
      res.status(400).type("html").send(loginPage(config, { error: "Enter a clerk name and passphrase.", username }));
      return;
    }
    const session = await authenticate(config, username, password);
    if (!session) {
      res.status(401).type("html").send(loginPage(config, { error: "Those desk credentials were not accepted.", username }));
      return;
    }
    res.setHeader("Set-Cookie", sessionCookie(issueSession(config, session), 8 * 60 * 60));
    res.redirect(302, "/app/");
  });

  router.post("/logout", (_req, res) => {
    res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; Path=/app; HttpOnly; SameSite=Lax; Max-Age=0`);
    res.redirect(302, "/app/login");
  });

  router.get("/", requireOperator, (req, res) => {
    res.type("html").send(appShell(config, sessionOf(req), "overview", "The Desk", overviewPage(config)));
  });

  router.get("/shards", requireOperator, async (req, res) => {
    res.type("html").send(appShell(config, sessionOf(req), "shards", "The Open Burn", await shardsPage(config)));
  });

  router.get("/source", requireOperator, (req, res) => {
    res.type("html").send(appShell(config, sessionOf(req), "source", "The Ash-Vault", sourcePage(config)));
  });

  router.get("/operations", requireOperator, (req, res) => {
    res.type("html").send(appShell(config, sessionOf(req), "operations", "Procedure", operationsPage()));
  });

  router.get("/status", requireOperator, (req, res) => {
    res.type("html").send(appShell(config, sessionOf(req), "status", "Instrument", statusPage(config)));
  });

  router.get("/api/status", (_req, res) => {
    res.json({
      service: "phantom_burn-app",
      status: "online",
      registry: config.registryAddress,
      archiveBundle: config.archiveBundle,
      network: "anvil-31337"
    });
  });

  router.get("/api/shards/recent", async (_req, res, next) => {
    try {
      const logs = await recentShardFilings(config);
      res.json({ filings: logs.map((log) => ({ blockNumber: log.blockNumber?.toString(), args: log.args })) });
    } catch (error) {
      next(error);
    }
  });

  router.post("/api/source/unlock", express.json(), async (req, res, next) => {
    try {
      const receipt = req.body as UnlockReceipt;
      const principal = String(req.header("x-archive-principal") ?? "");
      const result = await verifyUnlockReceipt(config, receipt, principal);
      if (!result.ok) {
        res.status(400).json({ error: "invalid receipt" });
        return;
      }

      if (!consumeUnlockReceipt(result.receiptId)) {
        res.status(409).json({ error: "receipt already consumed" });
        return;
      }

      const token = issueArchiveToken(result.verified);
      res.json({
        archive: config.archiveBundle,
        download: `/api/source/bundle?shardId=${encodeURIComponent(result.verified.shardId)}&txHash=${encodeURIComponent(result.verified.txHash)}`,
        token,
        message: "source bundle token issued"
      });
    } catch (error) {
      next(error);
    }
  });

  router.get("/api/source/bundle", (req, res) => {
    const bearer = String(req.header("authorization") ?? "");
    const token = bearer.startsWith("Bearer ") ? bearer.slice(7) : String(req.query.token ?? "");
    if (!verifyArchiveToken(token, {
      shardId: String(req.query.shardId ?? ""),
      txHash: String(req.query.txHash ?? "")
    })) {
      res.status(400).json({ error: "invalid receipt" });
      return;
    }

    const bundle = path.resolve(process.cwd(), config.archiveBundle);
    if (!fs.existsSync(bundle)) {
      res.status(404).json({ error: "source bundle missing" });
      return;
    }

    res.download(bundle, "archive-service.locked.tar.gz");
  });

  return router;
}
