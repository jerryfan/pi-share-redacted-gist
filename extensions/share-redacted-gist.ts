import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

type ShareArgs = {
	sessionPath?: string;
	description?: string;
	topic?: string;
	language?: string;
	tags?: string;
	yes: boolean;
	noReview: boolean;
};

type RedactionRule = {
	label: string;
	pattern: RegExp;
	replace: string;
};

type RedactionStat = {
	label: string;
	count: number;
};

type OpenAgentSessionsMetadata = {
	schema_version: "1.0";
	license: "CC0-1.0";
	consent_confirmed: true;
	redaction_done: true;
	created_at: string;
	session: {
		agent: "pi-coding-agent";
		model: string;
		language: string;
		topic: string;
	};
	tags: string[];
	redaction_stats: RedactionStat[];
};

const COMMAND_NAME = "share-redacted";

export default function shareRedactedGist(pi: ExtensionAPI) {
	pi.registerCommand(COMMAND_NAME, {
		description: "Publish redacted pi session + openagentsessions.json as public GitHub gist",
		handler: async (rawArgs, ctx) => {
			const args = parseArgs(rawArgs);
			if (args instanceof Error) {
				ctx.ui.notify(args.message, "error");
				return;
			}

			const sessionPath = args.sessionPath
				? resolvePath(ctx.cwd, args.sessionPath)
				: (ctx.sessionManager.getSessionFile() ?? undefined);
			if (!sessionPath) {
				ctx.ui.notify("No persisted session file. Pass --session @/path/to/session.jsonl", "error");
				return;
			}

			let rawSession = "";
			try {
				rawSession = await fs.readFile(sessionPath, "utf8");
			} catch (error) {
				ctx.ui.notify(`Failed reading session file: ${toErrorMessage(error)}`, "error");
				return;
			}

			const { text: redactedSession, stats } = redactSensitive(rawSession, {
				cwd: ctx.cwd,
				homeDir: os.homedir(),
				usernameCandidates: collectUsernames(),
			});

			let finalSessionText = redactedSession;
			if (ctx.hasUI && !args.noReview) {
				const edited = await ctx.ui.editor("Review redacted session file before publish", redactedSession);
				if (edited === undefined) {
					ctx.ui.notify("Cancelled", "info");
					return;
				}
				finalSessionText = edited;
			}

			const consentConfirmed = await confirmAttestation(ctx, args.yes, sessionPath, stats);
			if (!consentConfirmed) {
				ctx.ui.notify("Attestation not confirmed. Stopped.", "warning");
				return;
			}

			const modelHint = extractModelFromSession(rawSession) ?? extractCurrentModel(ctx.model) ?? "unknown";
			const language = await resolveField(ctx, args.language, "Language", "Session language", "typescript");
			if (!language) return;
			const topic = await resolveField(ctx, args.topic, "Topic", "Session topic", "general coding task");
			if (!topic) return;
			const tags = await resolveTags(ctx, args.tags, topic);
			if (!tags) return;

			const metadata: OpenAgentSessionsMetadata = {
				schema_version: "1.0",
				license: "CC0-1.0",
				consent_confirmed: true,
				redaction_done: true,
				created_at: isoTimestamp(),
				session: {
					agent: "pi-coding-agent",
					model: modelHint,
					language,
					topic,
				},
				tags,
				redaction_stats: stats,
			};

			const tmpDir = path.join(os.tmpdir(), `pi-openagentsession-${Date.now()}`);
			const sessionFilename = redactedSessionFilename(sessionPath);
			const sessionOut = path.join(tmpDir, sessionFilename);
			const metadataOut = path.join(tmpDir, "openagentsessions.json");

			try {
				await fs.mkdir(tmpDir, { recursive: true });
				await fs.writeFile(sessionOut, finalSessionText, "utf8");
				await fs.writeFile(metadataOut, `${JSON.stringify(metadata, null, 2)}\n`, "utf8");
			} catch (error) {
				ctx.ui.notify(`Failed writing gist files: ${toErrorMessage(error)}`, "error");
				return;
			}

			const description = args.description ?? "Open agent session (CC0)";
			const gist = await pi.exec("gh", ["gist", "create", sessionOut, metadataOut, "--public", "--desc", description]);
			if (gist.code !== 0) {
				ctx.ui.notify(`gh gist create failed: ${gist.stderr.trim() || gist.stdout.trim()}`, "error");
				return;
			}

			const url = extractGistUrl(`${gist.stdout}\n${gist.stderr}`) ?? gist.stdout.trim();
			ctx.ui.notify(`Public gist created: ${url}`, "info");
			ctx.ui.notify("Submit: openagentsessions.org/submit → paste gist URL → attest → submit", "info");
		},
	});
}

function parseArgs(raw: string): ShareArgs | Error {
	const tokens = tokenizeArgs(raw.trim());
	const args: ShareArgs = { yes: false, noReview: false };

	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i]!;
		if (token === "--help") {
			return new Error(
				"Usage: /share-redacted [--session @path] [--desc \"text\"] [--topic \"text\"] [--language ts] [--tags a,b] [--no-review] [--yes]",
			);
		}
		if (token === "--yes") {
			args.yes = true;
			continue;
		}
		if (token === "--no-review") {
			args.noReview = true;
			continue;
		}
		if (token === "--session") {
			const value = tokens[i + 1];
			if (!value) return new Error("Missing value for --session");
			args.sessionPath = stripAtPrefix(value);
			i++;
			continue;
		}
		if (token === "--desc" || token === "--description") {
			const value = tokens[i + 1];
			if (!value) return new Error(`Missing value for ${token}`);
			args.description = value;
			i++;
			continue;
		}
		if (token === "--topic") {
			const value = tokens[i + 1];
			if (!value) return new Error("Missing value for --topic");
			args.topic = value;
			i++;
			continue;
		}
		if (token === "--language") {
			const value = tokens[i + 1];
			if (!value) return new Error("Missing value for --language");
			args.language = value;
			i++;
			continue;
		}
		if (token === "--tags") {
			const value = tokens[i + 1];
			if (!value) return new Error("Missing value for --tags");
			args.tags = value;
			i++;
			continue;
		}
		if (token.startsWith("--")) return new Error(`Unknown flag: ${token}`);
		if (!args.sessionPath) {
			args.sessionPath = stripAtPrefix(token);
			continue;
		}
		return new Error(`Unexpected argument: ${token}`);
	}

	return args;
}

async function confirmAttestation(
	ctx: { hasUI: boolean; ui: { confirm: (title: string, message: string) => Promise<boolean> } },
	yes: boolean,
	sessionPath: string,
	stats: RedactionStat[],
): Promise<boolean> {
	if (yes) return true;
	if (!ctx.hasUI) return false;

	const summary = stats.length > 0 ? stats.map((s) => `${s.label}:${s.count}`).join(", ") : "no pattern matches";
	return ctx.ui.confirm(
		"Attestation required (openagentsessions)",
		[
			"I confirm all of the following:",
			"- I have rights to publish this session",
			"- secrets/private data are redacted",
			"- I intend to publish under CC0-1.0",
			"",
			`Session: ${path.basename(sessionPath)}`,
			`Redaction summary: ${summary}`,
			"",
			"Continue and create PUBLIC gist?",
		].join("\n"),
	);
}

async function resolveField(
	ctx: { hasUI: boolean; ui: { input: (title: string, placeholder?: string) => Promise<string | undefined> } },
	provided: string | undefined,
	label: string,
	placeholder: string,
	fallback: string,
): Promise<string | undefined> {
	if (provided?.trim()) return provided.trim();
	if (!ctx.hasUI) return fallback;
	const value = await ctx.ui.input(label, placeholder);
	if (value === undefined) return undefined;
	return value.trim() || fallback;
}

async function resolveTags(
	ctx: { hasUI: boolean; ui: { input: (title: string, placeholder?: string) => Promise<string | undefined> } },
	tagsArg: string | undefined,
	topic: string,
): Promise<string[] | undefined> {
	const seed = tagsArg ?? topic;
	if (seed.trim()) {
		const tags = splitTags(seed);
		if (tags.length > 0) return tags;
	}
	if (!ctx.hasUI) return [];
	const typed = await ctx.ui.input("Tags", "comma-separated tags, e.g. bugfix,auth");
	if (typed === undefined) return undefined;
	return splitTags(typed);
}

function splitTags(input: string): string[] {
	return [...new Set(input.split(",").map((part) => part.trim().toLowerCase()).filter(Boolean))];
}

function extractModelFromSession(rawSession: string): string | undefined {
	const lines = rawSession.split(/\r?\n/);
	for (const line of lines) {
		if (!line.trim()) continue;
		let parsed: unknown;
		try {
			parsed = JSON.parse(line);
		} catch {
			continue;
		}
		if (!isRecord(parsed) || parsed.type !== "message" || !isRecord(parsed.message)) continue;
		const message = parsed.message;
		if (message.role !== "assistant") continue;
		const model = typeof message.model === "string" ? message.model : undefined;
		const provider = typeof message.provider === "string" ? message.provider : undefined;
		if (model && provider) return `${provider}/${model}`;
		if (model) return model;
	}
	return undefined;
}

function extractCurrentModel(model: unknown): string | undefined {
	if (!isRecord(model)) return undefined;
	const id = typeof model.id === "string" ? model.id : undefined;
	const provider = typeof model.provider === "string" ? model.provider : undefined;
	if (id && provider) return `${provider}/${id}`;
	return id;
}

function redactedSessionFilename(sessionPath: string): string {
	const base = path.basename(sessionPath);
	if (base.endsWith(".jsonl")) return `${base.slice(0, -6)}.redacted.jsonl`;
	const ext = path.extname(base);
	if (!ext) return `${base}.redacted.txt`;
	return `${base.slice(0, -ext.length)}.redacted${ext}`;
}

function redactSensitive(
	text: string,
	options: { cwd: string; homeDir: string; usernameCandidates: string[] },
): { text: string; stats: RedactionStat[] } {
	const rules: RedactionRule[] = [
		{ label: "email", pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, replace: "[REDACTED_EMAIL]" },
		{
			label: "phone",
			pattern: /\b(?:\+\d{1,3}[\s-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s-]\d{3,4}[\s-]\d{3,4}\b/g,
			replace: "[REDACTED_PHONE]",
		},
		{
			label: "ipv4",
			pattern: /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g,
			replace: "[REDACTED_IP]",
		},
		{ label: "github_token", pattern: /\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})\b/g, replace: "[REDACTED_TOKEN]" },
		{
			label: "api_key",
			pattern: /\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g,
			replace: "[REDACTED_SECRET]",
		},
		{ label: "jwt", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, replace: "[REDACTED_JWT]" },
		{ label: "home_path", pattern: /\/home\/[^/\s]+\//g, replace: "/home/[REDACTED_USER]/" },
		{ label: "windows_path", pattern: /[A-Za-z]:\\Users\\[^\\\s]+\\/g, replace: "C:\\Users\\[REDACTED_USER]\\" },
		{ label: "private_url", pattern: /https?:\/\/[^\s"']+\.(?:local|internal|lan)\b/gi, replace: "[REDACTED_PRIVATE_URL]" },
	];

	if (options.cwd.trim()) {
		rules.push({ label: "cwd", pattern: new RegExp(escapeRegExp(options.cwd), "g"), replace: "[REDACTED_CWD]" });
	}
	if (options.homeDir.trim()) {
		rules.push({
			label: "home_dir",
			pattern: new RegExp(escapeRegExp(options.homeDir), "g"),
			replace: "/home/[REDACTED_USER]",
		});
	}
	for (const username of options.usernameCandidates) {
		if (username.length < 3) continue;
		rules.push({
			label: "username",
			pattern: new RegExp(`\\b${escapeRegExp(username)}\\b`, "g"),
			replace: "[REDACTED_USER]",
		});
	}

	let output = text;
	const stats: RedactionStat[] = [];
	for (const rule of rules) {
		let count = 0;
		output = output.replace(rule.pattern, () => {
			count += 1;
			return rule.replace;
		});
		if (count > 0) stats.push({ label: rule.label, count });
	}
	return { text: output, stats };
}

function tokenizeArgs(input: string): string[] {
	if (!input.trim()) return [];
	const tokens: string[] = [];
	let current = "";
	let quote: '"' | "'" | null = null;
	for (let i = 0; i < input.length; i++) {
		const ch = input[i]!;
		if (quote) {
			if (ch === quote) quote = null;
			else current += ch;
			continue;
		}
		if (ch === '"' || ch === "'") {
			quote = ch;
			continue;
		}
		if (/\s/.test(ch)) {
			if (current) {
				tokens.push(current);
				current = "";
			}
			continue;
		}
		current += ch;
	}
	if (current) tokens.push(current);
	return tokens;
}

function stripAtPrefix(value: string): string {
	return value.startsWith("@") ? value.slice(1) : value;
}

function resolvePath(cwd: string, value: string): string {
	const normalized = stripAtPrefix(value);
	return path.isAbsolute(normalized) ? normalized : path.resolve(cwd, normalized);
}

function extractGistUrl(text: string): string | undefined {
	const match = text.match(/https:\/\/gist\.github\.com\/\S+/);
	return match?.[0];
}

function collectUsernames(): string[] {
	const candidates = [path.basename(os.homedir()), process.env.USER ?? "", process.env.USERNAME ?? ""];
	try {
		candidates.unshift(os.userInfo().username);
	} catch {}
	return [...new Set(candidates.map((entry) => entry.trim()).filter(Boolean))];
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) return error.message;
	return String(error);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

function isoTimestamp(): string {
	return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
