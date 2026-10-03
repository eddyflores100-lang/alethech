// TypeScript/JavaScript SDK for alethech
// Second independent implementation for cross-validation
// Uses Web Crypto API (Ed25519 + SHA-256) — no dependencies

export interface KeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    publicKeyBytes: Uint8Array;
}

export interface Identity {
    type: string;
    version: number;
    agent_id: string;
    public_key: { kty: string; crv: string; x: string };
    key_id: string;
    created_at: string;
    recovery_root: string;
}

export interface MemoryCommit {
    type: string;
    version: number;
    agent_id: string;
    key_id: string;
    parents: string[];
    timestamp: string;
    session_id: string;
    memory_type: string;
    content: Record<string, unknown>;
    provenance: Record<string, unknown>;
    commit_id: string;
    signature: string;
}

// ============ CRYPTO ============

export async function generateKeyPair(): Promise<KeyPair> {
    const keyPair = await crypto.subtle.generateKey(
        { name: "Ed25519" },
        true,
        ["sign", "verify"]
    );

    const pubKeyRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    const publicKeyBytes = new Uint8Array(pubKeyRaw);

    return {
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        publicKeyBytes,
    };
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
    const hash = await crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(hash);
}

export function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
    const buf = await sha256(data);
    return bytesToHex(buf);
}

export function bytesToBase64Url(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlToBytes(s: string): Uint8Array {
    let padded = s.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4 !== 0) padded += "=";
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

export function bytesToBase32Lower(bytes: Uint8Array): string {
    const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    let result = "";
    let buffer = 0;
    let bitsLeft = 0;

    for (const byte of bytes) {
        buffer = (buffer << 8) | byte;
        bitsLeft += 8;
        while (bitsLeft >= 5) {
            bitsLeft -= 5;
            const index = (buffer >> bitsLeft) & 0x1f;
            result += alphabet[index];
        }
    }
    if (bitsLeft > 0) {
        const index = (buffer << (5 - bitsLeft)) & 0x1f;
        result += alphabet[index];
    }
    return result;
}

export async function deriveAgentId(publicKeyBytes: Uint8Array): Promise<string> {
    const x = bytesToBase64Url(publicKeyBytes);
    // Protocol rule: hash the JCS-canonical JWK, not insertion-order JSON.
    const jwk = canonicalizeJson({ kty: "OKP", crv: "Ed25519", x });
    const jwkBytes = new TextEncoder().encode(jwk);
    const hash = await sha256(jwkBytes);
    const b32 = bytesToBase32Lower(hash.slice(0, 16));
    return `did:alethech:${b32}`;
}

export async function sign(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
    const sig = await crypto.subtle.sign("Ed25519", privateKey, data);
    return new Uint8Array(sig);
}

export async function verify(
    publicKey: CryptoKey,
    signature: Uint8Array,
    data: Uint8Array
): Promise<boolean> {
    try {
        return await crypto.subtle.verify("Ed25519", publicKey, signature, data);
    } catch {
        return false;
    }
}

// ============ JCS CANONICALIZATION (RFC 8785) ============

export function canonicalizeJson(value: unknown): string {
    if (value === null) return "null";
    if (value === true) return "true";
    if (value === false) return "false";
    if (typeof value === "number") return serializeNumber(value);
    if (typeof value === "string") return escapeString(value);
    if (Array.isArray(value)) {
        return `[${value.map(canonicalizeJson).join(",")}]`;
    }
    if (typeof value === "object") {
        const obj = value as Record<string, unknown>;
        const sortedKeys = Object.keys(obj).sort((a, b) => {
            const aCodes: number[] = [];
            const bCodes: number[] = [];
            for (let i = 0; i < a.length; i++) aCodes.push(a.charCodeAt(i));
            for (let i = 0; i < b.length; i++) bCodes.push(b.charCodeAt(i));
            for (let i = 0; i < Math.min(aCodes.length, bCodes.length); i++) {
                if (aCodes[i] !== bCodes[i]) return aCodes[i] - bCodes[i];
            }
            return aCodes.length - bCodes.length;
        });
        const parts = sortedKeys.map(k => `${escapeString(k)}:${canonicalizeJson(obj[k])}`);
        return `{${parts.join(",")}}`;
    }
    return "null";
}

function escapeString(s: string): string {
    let out = '"';
    for (const ch of s) {
        const code = ch.charCodeAt(0);
        if (ch === '"') out += '\\"';
        else if (ch === "\\") out += "\\\\";
        else if (ch === "\n") out += "\\n";
        else if (ch === "\r") out += "\\r";
        else if (ch === "\t") out += "\\t";
        else if (ch === "\b") out += "\\b";
        else if (ch === "\f") out += "\\f";
        else if (code < 0x20) out += `\\u${code.toString(16).padStart(4, "0")}`;
        else out += ch;
    }
    out += '"';
    return out;
}

function serializeNumber(n: number): string {
    if (n === 0) return "0";
    if (!Number.isFinite(n)) throw new Error("NaN/Infinity not representable in JCS");
    if (Number.isInteger(n)) return n.toString();

    const abs = Math.abs(n);
    if (abs >= 1e21 || abs < 1e-6) {
        const s = n.toExponential();
        return s.replace(/e([+-]?\d)/, (match, exp) => {
            const num = parseInt(exp);
            return num >= 0 ? `e+${num}` : `e-${Math.abs(num)}`;
        });
    }
    return n.toString();
}

// ============ OBJECTS ============

export function utcNow(): string {
    return new Date().toISOString().replace(/\.\d+Z$/, ".000Z");
}

export async function createIdentity(kp: KeyPair, keyId: string): Promise<Identity> {
    const x = bytesToBase64Url(kp.publicKeyBytes);
    const agentId = await deriveAgentId(kp.publicKeyBytes);

    return {
        type: "Identity",
        version: 1,
        agent_id: agentId,
        public_key: { kty: "OKP", crv: "Ed25519", x },
        key_id: keyId,
        created_at: utcNow(),
        recovery_root: "",
    };
}

export async function createCommit(
    agentId: string,
    keyId: string,
    parents: string[],
    content: Record<string, unknown>,
    kp: KeyPair
): Promise<MemoryCommit> {
    // Hashing and signing must use the same caller-approved immutable inputs.
    parents = [...parents];
    content = structuredClone(content);
    const privateKey = kp.privateKey;
    const timestamp = utcNow();
    const signable: Record<string, unknown> = {
        type: "MemoryCommit",
        version: 1,
        agent_id: agentId,
        key_id: keyId,
        parents,
        timestamp,
        session_id: "",
        memory_type: "semantic",
        content,
        provenance: {},
    };

    const canonical = canonicalizeJson(signable);
    const canonicalBytes = new TextEncoder().encode(canonical);
    const hash = await sha256(canonicalBytes);
    const commitId = `sha256:${bytesToHex(hash)}`;

    const signableWithId = { ...signable, commit_id: commitId };
    const canonicalWithId = canonicalizeJson(signableWithId);
    const signableBytes = new TextEncoder().encode(canonicalWithId);
    const sig = await sign(privateKey, signableBytes);

    return {
        ...signableWithId as any,
        signature: `ed25519:${bytesToBase64Url(sig)}`,
    } as MemoryCommit;
}

export async function verifyCommit(
    commit: MemoryCommit,
    publicKeyBytes: Uint8Array
): Promise<boolean> {
    commit = structuredClone(commit);
    publicKeyBytes = new Uint8Array(publicKeyBytes);
    if (!commit.signature.startsWith("ed25519:")) return false;

    const sigB64 = commit.signature.slice(8);
    const sigBytes = base64UrlToBytes(sigB64);
    if (sigBytes.length !== 64) return false;

    // Integrity rule: commit_id MUST equal SHA-256(JCS(commit without
    // commit_id/signature)); a valid signature over an arbitrary ID is not enough.
    const { signature, commit_id, ...body } = commit;
    const bodyBytes = new TextEncoder().encode(canonicalizeJson(body));
    const expectedId = `sha256:${await sha256Hex(bodyBytes)}`;
    if (commit_id !== expectedId) return false;

    const rest = { ...body, commit_id };
    const canonical = canonicalizeJson(rest);
    const data = new TextEncoder().encode(canonical);

    const pubKey = await crypto.subtle.importKey(
        "raw",
        publicKeyBytes,
        { name: "Ed25519" },
        false,
        ["verify"]
    );

    return verify(pubKey, sigBytes, data);
}

// ============ ANCESTRY CHECK ============

export function ancestryCheck(
    commitId: string,
    cutoffHead: string,
    commits: Map<string, MemoryCommit>
): boolean {
    if (commitId === cutoffHead) return true;

    const visited = new Set<string>();
    const queue: string[] = [cutoffHead];

    while (queue.length > 0) {
        const current = queue.shift()!;
        if (visited.has(current)) continue;
        visited.add(current);

        if (current === commitId) return true;

        const commit = commits.get(current);
        if (commit) {
            for (const parent of commit.parents) {
                if (!visited.has(parent)) queue.push(parent);
            }
        }
    }

    return false;
}

// ============ TESTS ============

export async function runTests(): Promise<{ passed: number; failed: number; results: string[] }> {
    const results: string[] = [];
    let passed = 0;
    let failed = 0;

    function assert(condition: boolean, name: string) {
        if (condition) {
            passed++;
            results.push(`PASS ${name}`);
        } else {
            failed++;
            results.push(`FAIL ${name}`);
        }
    }

    const kp = await generateKeyPair();
    const msg = new TextEncoder().encode("hello alethech");
    const sig = await sign(kp.privateKey, msg);
    assert(await verify(kp.publicKey, sig, msg), "Ed25519 sign + verify");

    const tampered = new Uint8Array(msg);
    tampered[0] ^= 0x01;
    assert(!await verify(kp.publicKey, sig, tampered), "Ed25519 tamper detection");

    const hashAbc = await sha256Hex(new TextEncoder().encode("abc"));
    assert(hashAbc === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 NIST vector abc");

    const hashEmpty = await sha256Hex(new Uint8Array(0));
    assert(hashEmpty === "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256 NIST vector empty");

    assert(bytesToBase32Lower(new TextEncoder().encode("foobar")) === "mzxw6ytboi", "Base32 RFC 4648 vector");

    const pk = new Uint8Array(32).fill(42);
    const id1 = await deriveAgentId(pk);
    const id2 = await deriveAgentId(pk);
    assert(id1 === id2 && id1.startsWith("did:alethech:"), "Agent ID deterministic");
    assert(id1 === "did:alethech:jcsjojphm7rtqmxq2hrrf7ooni", "Agent ID Python/JCS conformance vector");

    assert(canonicalizeJson({ b: 1, a: 2 }) === `{"a":2,"b":1}`, "JCS key sorting");

    assert(canonicalizeJson({ b: { d: 1, c: 2 }, a: 3 }) === `{"a":3,"b":{"c":2,"d":1}}`, "JCS nested");

    assert(canonicalizeJson(-0) === "0", "JCS -0 to 0 RFC 8785 erratum");

    assert(canonicalizeJson(3.0) === "3", "JCS 3.0 to 3");

    const ident = await createIdentity(kp, "key-001");
    const commit = await createCommit(ident.agent_id, "key-001", [], { test: true }, kp);
    assert(await verifyCommit(commit, kp.publicKeyBytes), "Commit sign + verify");

    const tamperedCommit = { ...commit, content: { test: false } };
    assert(!await verifyCommit(tamperedCommit as MemoryCommit, kp.publicKeyBytes), "Commit tamper detection");

    // Mutation guard: a signer can sign an arbitrary commit_id, but the verifier
    // must still reject it when the ID is not the hash of the content.
    const { signature: _sig, commit_id: _id, ...body } = commit;
    const wrongId = `sha256:${"0".repeat(64)}`;
    const forgedSignable = { ...body, commit_id: wrongId };
    const forgedBytes = new TextEncoder().encode(canonicalizeJson(forgedSignable));
    const forgedSig = await sign(kp.privateKey, forgedBytes);
    const forgedCommit = {
        ...forgedSignable,
        signature: `ed25519:${bytesToBase64Url(forgedSig)}`,
    } as MemoryCommit;
    assert(!await verifyCommit(forgedCommit, kp.publicKeyBytes), "Commit ID integrity mutation guard");

    const commit1 = await createCommit(ident.agent_id, "key-001", [], { v: 1 }, kp);
    const commit2 = await createCommit(ident.agent_id, "key-001", [], { v: 2 }, kp);
    assert(commit1.commit_id !== commit2.commit_id, "Commit ID changes with content");

    assert(ancestryCheck("c1", "c1", new Map()), "Ancestry direct self");

    const commits = new Map<string, MemoryCommit>();
    commits.set(commit1.commit_id, commit1);
    commits.set(commit2.commit_id, commit2);
    assert(!ancestryCheck(commit2.commit_id, commit1.commit_id, commits), "Ancestry unreachable");

    return { passed, failed, results };
}
