"use strict";

const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { Server } = require("socket.io");

const app = express();
app.set("trust proxy", 1);

const isProduction = process.env.NODE_ENV === "production";
const allowedOrigins = (process.env.ALLOWED_ORIGIN || (isProduction ? "" : "http://localhost:3000,http://127.0.0.1:3000"))
  .split(",").map(value => value.trim()).filter(Boolean);

if (isProduction && allowedOrigins.length === 0) {
  throw new Error("ALLOWED_ORIGIN must be set to the exact HTTPS application origin in production.");
}

function originAllowed(origin) {
  return Boolean(origin && allowedOrigins.includes(origin));
}

app.use((req, res, next) => {
  if (isProduction && req.get("x-forwarded-proto") !== "https") {
    return res.redirect(308, `https://${req.get("host")}${req.originalUrl}`);
  }
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; worker-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()");
  if (isProduction) res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  next();
});

const publicDirectory = path.join(__dirname, "public");
const indexPath = path.join(publicDirectory, "index.html");

function templateSource() {
  return fs.readFileSync(indexPath, "utf8");
}

function extractedStyle() {
  const match = templateSource().match(/<style>([\s\S]*?)<\/style>/);
  if (!match) throw new Error("Client stylesheet is missing");
  return match[1];
}

function extractedClientScript() {
  const match = templateSource().match(/<script>([\s\S]*?)<\/script>/);
  if (!match) throw new Error("Client application script is missing");
  return match[1];
}

app.get("/", (_req, res) => {
  const page = templateSource()
    .replace(/<style>[\s\S]*?<\/style>/, '<link rel="stylesheet" href="/app.css">')
    .replace(/<script>[\s\S]*?<\/script>/, '<script src="/app.js" defer></script>');
  res.type("html").send(page);
});
app.get("/app.css", (_req, res) => res.type("text/css").send(extractedStyle()));
app.get("/app.js", (_req, res) => res.type("application/javascript").send(extractedClientScript()));
app.use(express.static(publicDirectory, { index: false, etag: true, maxAge: "1h" }));
app.use("/vendor/qrcode-generator", express.static(path.join(__dirname, "node_modules", "qrcode-generator"), { immutable: true, maxAge: "7d" }));
app.get("/health", (_req, res) => res.json({ ok: true }));

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin(origin, callback) {
      if (originAllowed(origin)) return callback(null, true);
      return callback(new Error("Origin is not allowed"));
    },
    methods: ["GET", "POST"],
    credentials: false,
  },
  allowRequest(req, callback) {
    callback(null, originAllowed(req.headers.origin));
  },
  perMessageDeflate: false,
  maxHttpBufferSize: 128 * 1024,
  pingInterval: 20_000,
  pingTimeout: 20_000,
});

const rooms = new Map();
const socketState = new Map();
const ROOM_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const PAIRING_TTL_MS = 10 * 60 * 1000;
const ACTIVE_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_CIPHERTEXT_CHARS = 72 * 1024;
const MAX_EVENTS_PER_MINUTE = 600;
const MAX_JOIN_ATTEMPTS_PER_MINUTE = 12;

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function token(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function roomCode() {
  const values = crypto.randomBytes(10);
  let output = "";
  for (let index = 0; index < 10; index += 1) output += ROOM_CODE_ALPHABET[values[index] % ROOM_CODE_ALPHABET.length];
  return output;
}

function validCode(value) {
  return typeof value === "string" && /^[A-HJ-NP-Z0-9]{10}$/.test(value);
}

function validPublicKey(value) {
  return typeof value === "string" && value.length >= 80 && value.length <= 512 && /^[A-Za-z0-9+/=_-]+$/.test(value);
}

function validCiphertext(value) {
  return typeof value === "string" && value.length > 20 && value.length <= MAX_CIPHERTEXT_CHARS;
}

function cleanExpiredRooms() {
  const now = Date.now();
  for (const [code, room] of rooms.entries()) {
    if (room.expiresAt <= now) {
      io.to(`room:${code}`).emit("room_closed", { reason: "This private room expired." });
      rooms.delete(code);
    }
  }
}

setInterval(cleanExpiredRooms, 60_000).unref();

function fail(ack, code, message) {
  if (typeof ack === "function") ack({ ok: false, code, message });
}

function allowEvent(socket, bucket = "events") {
  const state = socketState.get(socket.id);
  if (!state) return false;
  const now = Date.now();
  const limit = bucket === "joins" ? MAX_JOIN_ATTEMPTS_PER_MINUTE : MAX_EVENTS_PER_MINUTE;
  const current = state[bucket];
  if (now - current.windowStart > 60_000) {
    current.windowStart = now;
    current.count = 0;
  }
  current.count += 1;
  return current.count <= limit;
}

function roomForSocket(socket) {
  const state = socketState.get(socket.id);
  if (!state?.roomCode) return null;
  const room = rooms.get(state.roomCode);
  if (!room || room.expiresAt <= Date.now()) return null;
  return room;
}

function participant(room, socketId) {
  return room.hostSocketId === socketId || room.joinSocketId === socketId;
}

io.on("connection", socket => {
  socketState.set(socket.id, {
    roomCode: null,
    role: null,
    events: { windowStart: Date.now(), count: 0 },
    joins: { windowStart: Date.now(), count: 0 },
  });

  socket.on("create_room", (input, ack) => {
    if (!allowEvent(socket) || !validPublicKey(input?.hostPublicKey)) return fail(ack, "invalid_request", "Could not create a private room.");
    cleanExpiredRooms();
    let code;
    do { code = roomCode(); } while (rooms.has(code));
    const inviteSecret = token(32);
    const hostToken = token(32);
    const room = {
      code,
      hostSocketId: socket.id,
      hostTokenHash: sha256(hostToken),
      inviteSecretHash: sha256(inviteSecret),
      hostPublicKey: input.hostPublicKey,
      joinSocketId: null,
      joinPublicKey: null,
      pendingJoin: null,
      createdAt: Date.now(),
      expiresAt: Date.now() + PAIRING_TTL_MS,
      status: "pairing",
    };
    rooms.set(code, room);
    const state = socketState.get(socket.id);
    state.roomCode = code;
    state.role = "host";
    socket.join(`room:${code}`);
    ack?.({ ok: true, code, inviteSecret, hostToken, pairingExpiresAt: room.expiresAt });
  });

  socket.on("request_join", (input, ack) => {
    if (!allowEvent(socket, "joins")) return fail(ack, "rate_limited", "Too many join attempts. Wait one minute.");
    const code = String(input?.code || "").toUpperCase().trim();
    if (!validCode(code) || typeof input?.inviteSecret !== "string" || !validPublicKey(input?.joinPublicKey)) return fail(ack, "invalid_request", "The invite is invalid.");
    const room = rooms.get(code);
    if (!room || room.status !== "pairing" || room.expiresAt <= Date.now()) return fail(ack, "expired", "This invitation does not exist or has expired.");
    if (sha256(input.inviteSecret) !== room.inviteSecretHash) return fail(ack, "forbidden", "This phone is not authorized for this invitation.");
    if (room.pendingJoin || room.joinSocketId) return fail(ack, "occupied", "This private room already has a join request or connected peer.");
    const requestId = token(24);
    room.pendingJoin = { socketId: socket.id, requestId, joinPublicKey: input.joinPublicKey, requestedAt: Date.now() };
    const state = socketState.get(socket.id);
    state.roomCode = code;
    state.role = "joining";
    socket.join(`room:${code}`);
    socket.to(room.hostSocketId).emit("join_request", { requestId, joinPublicKey: input.joinPublicKey });
    ack?.({ ok: true, hostPublicKey: room.hostPublicKey, requestId, pairingExpiresAt: room.expiresAt });
  });

  socket.on("approve_join", (input, ack) => {
    if (!allowEvent(socket)) return fail(ack, "rate_limited", "Too many requests.");
    const room = roomForSocket(socket);
    if (!room || socket.id !== room.hostSocketId || room.status !== "pairing") return fail(ack, "forbidden", "Only the host can approve this pairing.");
    if (sha256(String(input?.hostToken || "")) !== room.hostTokenHash || input?.requestId !== room.pendingJoin?.requestId) return fail(ack, "forbidden", "The pairing approval was rejected.");
    const joining = room.pendingJoin;
    room.joinSocketId = joining.socketId;
    room.joinPublicKey = joining.joinPublicKey;
    room.pendingJoin = null;
    room.status = "active";
    room.expiresAt = Date.now() + ACTIVE_TTL_MS;
    const joinState = socketState.get(joining.socketId);
    if (joinState) joinState.role = "join";
    io.to(room.hostSocketId).emit("pairing_approved", { peerPublicKey: room.joinPublicKey, expiresAt: room.expiresAt });
    io.to(room.joinSocketId).emit("pairing_approved", { peerPublicKey: room.hostPublicKey, expiresAt: room.expiresAt });
    ack?.({ ok: true });
  });

  socket.on("reject_join", (input, ack) => {
    const room = roomForSocket(socket);
    if (!room || socket.id !== room.hostSocketId || sha256(String(input?.hostToken || "")) !== room.hostTokenHash) return fail(ack, "forbidden", "The join request could not be rejected.");
    if (room.pendingJoin) {
      io.to(room.pendingJoin.socketId).emit("join_rejected");
      const joinState = socketState.get(room.pendingJoin.socketId);
      if (joinState) { joinState.roomCode = null; joinState.role = null; }
      room.pendingJoin = null;
    }
    ack?.({ ok: true });
  });

  socket.on("relay_envelope", (input, ack) => {
    if (!allowEvent(socket)) return fail(ack, "rate_limited", "Sending too quickly. Slow down.");
    const room = roomForSocket(socket);
    if (!room || room.status !== "active" || !participant(room, socket.id) || !validCiphertext(input?.ciphertext)) return fail(ack, "forbidden", "The encrypted envelope was rejected.");
    socket.to(`room:${room.code}`).emit("encrypted_envelope", { ciphertext: input.ciphertext });
    ack?.({ ok: true });
  });

  socket.on("close_room", (input, ack) => {
    const room = roomForSocket(socket);
    if (!room || socket.id !== room.hostSocketId || sha256(String(input?.hostToken || "")) !== room.hostTokenHash) return fail(ack, "forbidden", "Only the host can close this room.");
    io.to(`room:${room.code}`).emit("room_closed", { reason: "The host closed the private room." });
    rooms.delete(room.code);
    ack?.({ ok: true });
  });

  socket.on("disconnect", () => {
    const state = socketState.get(socket.id);
    const room = state?.roomCode ? rooms.get(state.roomCode) : null;
    if (room) {
      if (room.pendingJoin?.socketId === socket.id) {
        room.pendingJoin = null;
        io.to(room.hostSocketId).emit("join_request_cancelled");
      } else {
        const peerId = room.hostSocketId === socket.id ? room.joinSocketId : room.hostSocketId;
        if (peerId) io.to(peerId).emit("peer_left");
        rooms.delete(room.code);
      }
    }
    socketState.delete(socket.id);
  });
});

const port = Number(process.env.PORT || 3000);
server.listen(port, () => console.log(`CipherLink relay listening on ${port}`));
