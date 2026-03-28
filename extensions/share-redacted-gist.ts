import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

import { resolveHuggingFaceAccessToken } from "./huggingface-auth";
import { getConfiguredDatasets, loadPublishConfig, type PublishConfig } from "./publish-config";
import { buildSubmissionMessage, publishToGist, publishToHuggingFace, type PublicationBundle, type PublisherChoice } from "./publishers";
import { redactSensitive, type RedactionStat } from "./redaction";
import { redactSensitiveFileToolPayloads } from "./sensitive-file-redaction";

export { buildSubmissionMessage } from "./publishers";

type ShareArgs = {
	sessionPath?: string;
	description?: string;
	topic?: string;
	language?: string;
	tags?: string;
	dataset?: string;
	publisher?: PublisherChoice;
	yes: boolean;
	noReview: boolean;
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
		description: "Publish redacted pi session to GitHub gist and/or Hugging Face dataset",
		handler: async (rawArgs, ctx) => {
			const args = parseArgs(rawArgs);
			if (args instanceof Error) {
				ctx.ui.notify(args.message, "error");
				return;
			}

			const publishConfig = loadPublishConfig(ctx.cwd);
			for (const warning of publishConfig.warnings) {
				ctx.ui.notify(warning, "warning");
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

			const sensitiveFilePass = redactSensitiveFileToolPayloads(rawSession, {
				enabled: publishConfig.config.redaction?.sensitiveFiles?.enabled,
				extraPatterns: publishConfig.config.redaction?.sensitiveFiles?.extraPatterns,
			});
			const genericPass = redactSensitive(sensitiveFilePass.text, {
				cwd: ctx.cwd,
				homeDir: os.homedir(),
				usernameCandidates: collectUsernames(),
			});
			const redactedSession = genericPass.text;
			const stats = mergeRedactionStats(sensitiveFilePass.stats, genericPass.stats);

			let finalSessionText = redactedSession;
			if (ctx.hasUI && !args.noReview) {
				const { reviewRedactions } = await importLocalModule<{ reviewRedactions: typeof import("./review-ui").reviewRedactions }>("review-ui.ts");
				const reviewed = await reviewRedactions(ctx, redactedSession);
				if (!reviewed) {
					ctx.ui.notify("Cancelled", "info");
					return;
				}
				finalSessionText = reviewed.text;
				if (reviewed.manualRuleCount > 0) {
					ctx.ui.notify(
						`Review applied ${reviewed.manualRuleCount} manual redaction rule(s); ${reviewed.remainingCandidates} suspicious value(s) left`,
						"info",
					);
				}
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

			const publisher = await resolvePublisherChoice(ctx, args, publishConfig.config);
			if (!publisher) return;

			let huggingFaceDataset: string | undefined;
			let huggingFaceToken: string | undefined;
			if (publisher === "huggingface" || publisher === "both") {
				huggingFaceDataset = await resolveHuggingFaceDataset(ctx, args, publishConfig.config);
				if (!huggingFaceDataset) {
					ctx.ui.notify("No Hugging Face dataset selected.", "error");
					return;
				}
				const auth = await resolveHuggingFaceAccessToken();
				if (!auth.token) {
					ctx.ui.notify(buildHuggingFaceAuthMessage(auth.authPath, auth.error), "error");
					return;
				}
				huggingFaceToken = auth.token;
			}

			const description = args.description ?? publishConfig.config.publishers?.gist?.description ?? "Open agent session (CC0)";
			const bundle: PublicationBundle = {
				sessionPath,
				sessionFilename: redactedSessionFilename(sessionPath),
				sessionText: finalSessionText,
				metadataText: `${JSON.stringify(metadata, null, 2)}\n`,
				createdAt: metadata.created_at,
				description,
			};

			const results = [];
			const failures = [];

			if (publisher === "gist" || publisher === "both") {
				try {
					results.push(await publishToGist(pi, bundle));
				} catch (error) {
					failures.push({ publisher: "gist" as const, message: toErrorMessage(error) });
				}
			}

			if ((publisher === "huggingface" || publisher === "both") && huggingFaceDataset && huggingFaceToken) {
				try {
					results.push(
						await publishToHuggingFace(bundle, {
							accessToken: huggingFaceToken,
							dataset: huggingFaceDataset,
							visibility: publishConfig.config.publishers?.huggingface?.visibility,
							pathPrefix: publishConfig.config.publishers?.huggingface?.pathPrefix,
						}),
					);
				} catch (error) {
					failures.push({ publisher: "huggingface" as const, message: toErrorMessage(error) });
				}
			}

			if (results.length === 0) {
				ctx.ui.notify(buildSubmissionMessage(results, failures), "error");
				return;
			}

			ctx.ui.notify(buildSubmissionMessage(results, failures), failures.length > 0 ? "warning" : "info");
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
				"Usage: /share-redacted [--session @path] [--desc \"text\"] [--topic \"text\"] [--language ts] [--tags a,b] [--publisher gist|huggingface|both] [--dataset owner/name] [--no-review] [--yes]",
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
		if (token === "--dataset") {
			const value = tokens[i + 1];
			if (!value) return new Error("Missing value for --dataset");
			args.dataset = value.trim();
			i++;
			continue;
		}
		if (token === "--publisher" || token === "--target") {
			const value = tokens[i + 1];
			if (!value) return new Error(`Missing value for ${token}`);
			const publisher = parsePublisherChoice(value);
			if (!publisher) return new Error(`Invalid publisher: ${value}`);
			args.publisher = publisher;
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

async function resolvePublisherChoice(
	ctx: { hasUI: boolean; ui: { select: (title: string, options: string[]) => Promise<string | undefined>; notify: (message: string, level: "info" | "warning" | "error") => void } },
	args: ShareArgs,
	config: PublishConfig,
): Promise<PublisherChoice | undefined> {
	if (args.publisher) return args.publisher;

	const gistEnabled = config.publishers?.gist?.enabled !== false;
	const huggingFaceEnabled = config.publishers?.huggingface?.enabled !== false && (getConfiguredDatasets(config).length > 0 || !!args.dataset);
	const available: PublisherChoice[] = [];
	if (gistEnabled) available.push("gist");
	if (huggingFaceEnabled) available.push("huggingface");

	if (available.length === 0) {
		ctx.ui.notify("No publishers configured. Enable gist and/or configure Hugging Face datasets.", "error");
		return undefined;
	}
	if (available.length === 1) return available[0];
	if (!ctx.hasUI) {
		ctx.ui.notify("Multiple publishers available. Pass --publisher gist|huggingface|both.", "error");
		return undefined;
	}

	const selection = await ctx.ui.select("Publish to", ["GitHub gist", "Hugging Face dataset", "Both"]);
	if (selection === undefined) return undefined;
	if (selection === "GitHub gist") return "gist";
	if (selection === "Hugging Face dataset") return "huggingface";
	return "both";
}

async function resolveHuggingFaceDataset(
	ctx: { hasUI: boolean; ui: { select: (title: string, options: string[]) => Promise<string | undefined> } },
	args: ShareArgs,
	config: PublishConfig,
): Promise<string | undefined> {
	if (args.dataset?.trim()) return args.dataset.trim();

	const datasets = getConfiguredDatasets(config);
	if (datasets.length === 0) return undefined;
	if (datasets.length === 1) return datasets[0];
	if (!ctx.hasUI) return config.publishers?.huggingface?.defaultDataset?.trim() || undefined;

	const defaultDataset = config.publishers?.huggingface?.defaultDataset?.trim();
	const options = defaultDataset && datasets.includes(defaultDataset)
		? [defaultDataset, ...datasets.filter((dataset) => dataset !== defaultDataset)]
		: datasets;
	return await ctx.ui.select("Hugging Face dataset", options);
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
			"Continue and publish?",
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

function mergeRedactionStats(...collections: ReadonlyArray<ReadonlyArray<RedactionStat>>): RedactionStat[] {
	const merged = new Map<string, number>();
	for (const collection of collections) {
		for (const entry of collection) {
			merged.set(entry.label, (merged.get(entry.label) ?? 0) + entry.count);
		}
	}
	return [...merged.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([label, count]) => ({ label, count }));
}

function redactedSessionFilename(sessionPath: string): string {
	const base = path.basename(sessionPath);
	if (base.endsWith(".jsonl")) return `${base.slice(0, -6)}.redacted.jsonl`;
	const ext = path.extname(base);
	if (!ext) return `${base}.redacted.txt`;
	return `${base.slice(0, -ext.length)}.redacted${ext}`;
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

function parsePublisherChoice(value: string): PublisherChoice | undefined {
	const normalized = value.trim().toLowerCase();
	if (normalized === "gist") return "gist";
	if (normalized === "huggingface" || normalized === "hf") return "huggingface";
	if (normalized === "both" || normalized === "all") return "both";
	return undefined;
}

function stripAtPrefix(value: string): string {
	return value.startsWith("@") ? value.slice(1) : value;
}

function resolvePath(cwd: string, value: string): string {
	const normalized = stripAtPrefix(value);
	return path.isAbsolute(normalized) ? normalized : path.resolve(cwd, normalized);
}

function buildHuggingFaceAuthMessage(authPath: string, detail?: string): string {
	const hint = [`No Hugging Face token. Set HF_TOKEN or add {\"huggingface\":{\"type\":\"api_key\",\"key\":\"hf_...\"}} to ${authPath}.`];
	if (detail) hint.push(detail);
	return hint.join(" ");
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

async function importLocalModule<T>(filename: string): Promise<T> {
	const currentFile = fileURLToPath(import.meta.url);
	const resolvedCurrentFile = await fs.realpath(currentFile).catch(() => currentFile);
	const moduleUrl = pathToFileURL(path.join(path.dirname(resolvedCurrentFile), filename)).href;
	return (await import(moduleUrl)) as T;
}

function isoTimestamp(): string {
	return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}
