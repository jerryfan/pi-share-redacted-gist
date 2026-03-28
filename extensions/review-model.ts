import { suggestPlaceholder } from "./review-apply";

export type ReviewModel = {
	blocks: ReviewBlock[];
	flaggedBlockCount: number;
	uniqueCandidateCount: number;
	totalOccurrences: number;
};

export type ReviewBlock = {
	id: string;
	index: number;
	title: string;
	subtitle?: string;
	text: string;
	lines: string[];
	summary: string;
	occurrences: ReviewOccurrence[];
	riskScore: number;
};

export type ReviewOccurrence = {
	id: string;
	signature: string;
	label: string;
	value: string;
	reason: string;
	suggestedPlaceholder: string;
	score: number;
	lineIndex: number;
	lineText: string;
	sessionCount: number;
};

type CandidateDraft = Omit<ReviewOccurrence, "id" | "sessionCount">;

type JsonRecord = Record<string, unknown>;

const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const URL_PATTERN = /https?:\/\/[^\s"')\]]+/gi;
const PATH_PATTERN = /(?:\/Users\/[^\s"'`()\[\]{}]+|\/home\/[^\s"'`()\[\]{}]+|[A-Za-z]:\\Users\\[^\\\s"'`()\[\]{}]+(?:\\[^\\\s"'`()\[\]{}]+)*)/g;
const HOSTNAME_PATTERN = /\b(?:localhost|[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+)(?::\d+)?\b/gi;
const IPV4_PATTERN = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g;
const IPV6_PRIVATE_PATTERN = /\b(?:fd|fc)[0-9a-f:]{6,}\b/gi;
const SECRET_CONTEXT_PATTERN = /\b(?:token|secret|api[_-]?key|auth|authorization|bearer|cookie|session|password|passwd|signature)\b/i;
const SECRET_ASSIGNMENT_PATTERN = /\b([A-Za-z][A-Za-z0-9_-]{1,40})\b\s*[:=]\s*("[^"]+"|'[^']+'|[^\s,;\]}]+)/g;
const BEARER_PATTERN = /\bBearer\s+([A-Za-z0-9._~+\/-]{8,})/g;
const OPAQUE_PATTERN = /[-A-Za-z0-9+/_=.]{16,}/g;
const SAFE_GIT_CONTEXT_PATTERN = /\b(?:commit|revision|sha|parent|tree|oid)\b/i;
const SAFE_HASH_CONTEXT_PATTERN = /\b(?:sha256|checksum|digest|integrity|hash)\b/i;
const REDACTED_PATTERN = /^\[REDACTED_[A-Z0-9_]+\]$/;

export function buildReviewModel(text: string, safeSignatures: ReadonlySet<string> = new Set()): ReviewModel {
	const blocks = parseReviewBlocks(text);
	const occurrenceCounts = new Map<string, number>();

	for (const block of blocks) {
		const deduped = dedupeOccurrences(detectBlockOccurrences(block)).filter((entry) => !safeSignatures.has(entry.signature));
		for (const entry of deduped) {
			occurrenceCounts.set(entry.signature, (occurrenceCounts.get(entry.signature) ?? 0) + 1);
		}
		block.occurrences = deduped;
	}

	let totalOccurrences = 0;
	for (const block of blocks) {
		block.occurrences = block.occurrences
			.map((entry, index) => ({
				...entry,
				id: `${block.id}-occ-${index}`,
				sessionCount: occurrenceCounts.get(entry.signature) ?? 1,
			}))
			.sort((a, b) => b.score - a.score || a.lineIndex - b.lineIndex || a.value.localeCompare(b.value));
		block.riskScore = block.occurrences.reduce((sum, entry) => sum + entry.score, 0);
		totalOccurrences += block.occurrences.length;
	}

	return {
		blocks,
		flaggedBlockCount: blocks.filter((block) => block.occurrences.length > 0).length,
		uniqueCandidateCount: occurrenceCounts.size,
		totalOccurrences,
	};
}

function parseReviewBlocks(text: string): ReviewBlock[] {
	const lines = text.split(/\r?\n/);
	const blocks: ReviewBlock[] = [];
	let blockIndex = 0;

	for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
		const line = lines[lineIndex]!;
		if (!line.trim()) continue;

		let parsed: unknown;
		try {
			parsed = JSON.parse(line);
		} catch {
			blocks.push(createBlock(blockIndex++, "Raw line", `line ${lineIndex + 1}`, line));
			continue;
		}

		if (!isRecord(parsed)) {
			blocks.push(createBlock(blockIndex++, "Raw value", `line ${lineIndex + 1}`, String(parsed)));
			continue;
		}

		if (parsed.type === "message" && isRecord(parsed.message)) {
			blocks.push(...extractMessageBlocks(blockIndex, parsed.message));
			blockIndex = blocks.length;
			continue;
		}

		if (parsed.type === "custom_message") {
			blocks.push(createBlock(blockIndex++, "Custom message", undefined, extractLooseText(parsed)));
			continue;
		}

		if (parsed.type === "session") continue;
		blocks.push(createBlock(blockIndex++, String(parsed.type ?? "Entry"), undefined, extractLooseText(parsed)));
	}

	if (blocks.length === 0) {
		blocks.push(createBlock(0, "Session", undefined, "(no transcript text)"));
	}
	return blocks;
}

function extractMessageBlocks(startIndex: number, message: JsonRecord): ReviewBlock[] {
	const blocks: ReviewBlock[] = [];
	const role = typeof message.role === "string" ? message.role : "message";

	if (role === "user") {
		blocks.push(createBlock(startIndex, "User", undefined, extractContentText(message.content)));
		return blocks;
	}

	if (role === "assistant") {
		const content = Array.isArray(message.content) ? message.content : [];
		const textParts = content
			.filter((entry) => isRecord(entry) && (entry.type === "text" || entry.type === "thinking"))
			.map((entry) => (entry.type === "text" ? String(entry.text ?? "") : String(entry.thinking ?? "")))
			.filter(Boolean);
		if (textParts.length > 0) {
			blocks.push(createBlock(startIndex + blocks.length, "Assistant", modelLabel(message), textParts.join("\n\n")));
		}
		for (const entry of content) {
			if (!isRecord(entry) || entry.type !== "toolCall") continue;
			const toolName = typeof entry.name === "string" ? entry.name : "tool";
			const args = isRecord(entry.arguments) || Array.isArray(entry.arguments) ? JSON.stringify(entry.arguments, null, 2) : String(entry.arguments ?? "");
			blocks.push(createBlock(startIndex + blocks.length, `Tool call · ${toolName}`, undefined, args || "(no arguments)"));
		}
		return blocks;
	}

	if (role === "toolResult") {
		const toolName = typeof message.toolName === "string" ? message.toolName : "tool";
		const text = extractContentText(message.content) || stringifyIfPresent(message.details) || "(no text output)";
		blocks.push(createBlock(startIndex, `Tool result · ${toolName}`, message.isError === true ? "error" : undefined, text));
		return blocks;
	}

	if (role === "bashExecution") {
		const command = typeof message.command === "string" ? message.command : "bash";
		const output = typeof message.output === "string" ? message.output : "";
		blocks.push(createBlock(startIndex, "User bash", command, [command, output].filter(Boolean).join("\n\n")));
		return blocks;
	}

	if (role === "custom") {
		const customType = typeof message.customType === "string" ? message.customType : "custom";
		blocks.push(createBlock(startIndex, `Custom · ${customType}`, undefined, extractContentText(message.content)));
		return blocks;
	}

	if (role === "branchSummary" || role === "compactionSummary") {
		const summary = typeof message.summary === "string" ? message.summary : "";
		blocks.push(createBlock(startIndex, role === "branchSummary" ? "Branch summary" : "Compaction summary", undefined, summary));
		return blocks;
	}

	blocks.push(createBlock(startIndex, role, undefined, extractLooseText(message)));
	return blocks;
}

function createBlock(index: number, title: string, subtitle: string | undefined, text: string): ReviewBlock {
	const normalized = normalizeBlockText(text);
	return {
		id: `block-${index}`,
		index,
		title,
		subtitle,
		text: normalized,
		lines: normalized.split(/\r?\n/),
		summary: firstMeaningfulLine(normalized),
		occurrences: [],
		riskScore: 0,
	};
}

function detectBlockOccurrences(block: ReviewBlock): CandidateDraft[] {
	const drafts: CandidateDraft[] = [];
	for (let lineIndex = 0; lineIndex < block.lines.length; lineIndex++) {
		const line = block.lines[lineIndex]!;
		if (!line.trim()) continue;
		detectSecretAssignments(block, line, lineIndex, drafts);
		detectBearerTokens(block, line, lineIndex, drafts);
		detectEmails(block, line, lineIndex, drafts);
		detectPaths(block, line, lineIndex, drafts);
		detectUrls(block, line, lineIndex, drafts);
		detectHostnames(block, line, lineIndex, drafts);
		detectPrivateIps(block, line, lineIndex, drafts);
		detectOpaqueValues(block, line, lineIndex, drafts);
	}
	return drafts;
}

function detectSecretAssignments(block: ReviewBlock, line: string, lineIndex: number, drafts: CandidateDraft[]): void {
	for (const match of line.matchAll(SECRET_ASSIGNMENT_PATTERN)) {
		const key = match[1] ?? "value";
		const rawValue = trimWrappedValue(match[2] ?? "");
		if (!looksSensitiveValue(rawValue)) continue;
		const keyScore = SECRET_CONTEXT_PATTERN.test(key) ? 115 : 90;
		drafts.push(buildDraft(block, lineIndex, line, rawValue, keyScore, `${key} value`, `Sensitive-looking value assigned to ${key}`, suggestPlaceholder(rawValue)));
	}
}

function detectBearerTokens(block: ReviewBlock, line: string, lineIndex: number, drafts: CandidateDraft[]): void {
	for (const match of line.matchAll(BEARER_PATTERN)) {
		const rawValue = sanitizeValue(match[1] ?? "");
		if (!looksSensitiveValue(rawValue)) continue;
		drafts.push(buildDraft(block, lineIndex, line, rawValue, 130, "Bearer token", "Authorization header style bearer token", "[REDACTED_SECRET]"));
	}
}

function detectEmails(block: ReviewBlock, line: string, lineIndex: number, drafts: CandidateDraft[]): void {
	for (const match of line.matchAll(EMAIL_PATTERN)) {
		const rawValue = sanitizeValue(match[0] ?? "");
		if (!looksSensitiveValue(rawValue)) continue;
		drafts.push(buildDraft(block, lineIndex, line, rawValue, 85, "Email", "Email address survived auto-redaction", "[REDACTED_EMAIL]"));
	}
}

function detectPaths(block: ReviewBlock, line: string, lineIndex: number, drafts: CandidateDraft[]): void {
	for (const match of line.matchAll(PATH_PATTERN)) {
		const rawValue = sanitizeValue(match[0] ?? "");
		if (!looksSensitiveValue(rawValue)) continue;
		drafts.push(buildDraft(block, lineIndex, line, rawValue, 82, "Path", "User or machine-specific filesystem path", suggestPlaceholder(rawValue)));
	}
}

function detectUrls(block: ReviewBlock, line: string, lineIndex: number, drafts: CandidateDraft[]): void {
	for (const match of line.matchAll(URL_PATTERN)) {
		const rawValue = sanitizeUrl(match[0] ?? "");
		if (!looksSensitiveValue(rawValue)) continue;
		if (!isSensitiveUrl(rawValue)) continue;
		drafts.push(buildDraft(block, lineIndex, line, rawValue, 98, "Private URL", "URL points at local, private, or internal-looking host", "[REDACTED_URL]"));
	}
}

function detectHostnames(block: ReviewBlock, line: string, lineIndex: number, drafts: CandidateDraft[]): void {
	for (const match of line.matchAll(HOSTNAME_PATTERN)) {
		const rawValue = sanitizeValue(match[0] ?? "");
		if (!looksSensitiveValue(rawValue)) continue;
		if (!isInternalHostname(rawValue)) continue;
		drafts.push(buildDraft(block, lineIndex, line, rawValue, 76, "Hostname", "Internal-looking hostname survived auto-redaction", "[REDACTED_HOST]"));
	}
}

function detectPrivateIps(block: ReviewBlock, line: string, lineIndex: number, drafts: CandidateDraft[]): void {
	for (const match of line.matchAll(IPV4_PATTERN)) {
		const rawValue = sanitizeValue(match[0] ?? "");
		if (!isPrivateIpv4(rawValue) || !looksSensitiveValue(rawValue)) continue;
		drafts.push(buildDraft(block, lineIndex, line, rawValue, 74, "Private IP", "Private IPv4 address survived auto-redaction", "[REDACTED_IP]"));
	}
	for (const match of line.matchAll(IPV6_PRIVATE_PATTERN)) {
		const rawValue = sanitizeValue(match[0] ?? "");
		if (!looksSensitiveValue(rawValue)) continue;
		drafts.push(buildDraft(block, lineIndex, line, rawValue, 70, "Private IPv6", "Private IPv6 address survived auto-redaction", "[REDACTED_IP]"));
	}
}

function detectOpaqueValues(block: ReviewBlock, line: string, lineIndex: number, drafts: CandidateDraft[]): void {
	for (const match of line.matchAll(OPAQUE_PATTERN)) {
		const rawValue = sanitizeValue(match[0] ?? "");
		if (!looksSensitiveValue(rawValue)) continue;
		if (rawValue.includes("/")) continue;
		const score = scoreOpaqueValue(rawValue, line);
		if (score === undefined) continue;
		drafts.push(buildDraft(block, lineIndex, line, rawValue, score, "Opaque token", "Random-looking token worth checking manually", "[REDACTED_SECRET]"));
	}
}

function buildDraft(
	block: ReviewBlock,
	lineIndex: number,
	line: string,
	value: string,
	score: number,
	label: string,
	reason: string,
	suggestedPlaceholder: string,
): CandidateDraft {
	return {
		signature: `literal:${value}`,
		label,
		value,
		reason,
		suggestedPlaceholder,
		score,
		lineIndex,
		lineText: line,
	};
}

function dedupeOccurrences(drafts: CandidateDraft[]): CandidateDraft[] {
	const byValue = new Map<string, CandidateDraft>();
	for (const draft of drafts) {
		const existing = byValue.get(draft.signature);
		if (!existing || draft.score > existing.score || (draft.score === existing.score && draft.lineIndex < existing.lineIndex)) {
			byValue.set(draft.signature, draft);
		}
	}
	return [...byValue.values()];
}

function extractContentText(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content
		.map((entry) => {
			if (!isRecord(entry)) return "";
			if (entry.type === "text") return String(entry.text ?? "");
			if (entry.type === "thinking") return String(entry.thinking ?? "");
			if (entry.type === "image") return "[image]";
			if (entry.type === "toolCall") return "";
			return JSON.stringify(entry);
		})
		.filter(Boolean)
		.join("\n");
}

function extractLooseText(value: unknown): string {
	if (typeof value === "string") return value;
	if (Array.isArray(value) || isRecord(value)) return JSON.stringify(value, null, 2);
	return String(value ?? "");
}

function stringifyIfPresent(value: unknown): string {
	if (value === undefined) return "";
	if (typeof value === "string") return value;
	if (Array.isArray(value) || isRecord(value)) return JSON.stringify(value, null, 2);
	return String(value);
}

function modelLabel(message: JsonRecord): string | undefined {
	const provider = typeof message.provider === "string" ? message.provider : undefined;
	const model = typeof message.model === "string" ? message.model : undefined;
	if (provider && model) return `${provider}/${model}`;
	return model;
}

function normalizeBlockText(text: string): string {
	const normalized = text.replace(/\r\n/g, "\n").trim();
	return normalized || "(empty)";
}

function firstMeaningfulLine(text: string): string {
	const line = text.split(/\r?\n/).find((entry) => entry.trim());
	if (!line) return "(empty)";
	return line.length > 72 ? `${line.slice(0, 69)}…` : line;
}

function trimWrappedValue(value: string): string {
	const trimmed = value.trim();
	if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
		return trimmed.slice(1, -1);
	}
	return sanitizeValue(trimmed);
}

function sanitizeValue(value: string): string {
	return value.replace(/^[({\["']+/, "").replace(/[),.;:\]}'"]+$/, "").trim();
}

function sanitizeUrl(value: string): string {
	return sanitizeValue(value).replace(/[)>]+$/, "");
}

function looksSensitiveValue(value: string): boolean {
	if (!value || value.length < 4) return false;
	if (REDACTED_PATTERN.test(value)) return false;
	if (/^(?:true|false|null|undefined)$/i.test(value)) return false;
	if (/^(?:yes|no|ok|none|error)$/i.test(value)) return false;
	return true;
}

function isSensitiveUrl(value: string): boolean {
	try {
		const url = new URL(value);
		return isInternalHostname(url.hostname) || isPrivateIpv4(url.hostname) || /^(?:\[)?(?:fd|fc)/i.test(url.hostname);
	} catch {
		return false;
	}
}

function isInternalHostname(hostname: string): boolean {
	const host = hostname.toLowerCase().replace(/:\d+$/, "");
	if (host === "localhost") return true;
	if (host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".lan") || host.endsWith(".home") || host.endsWith(".arpa") || host.endsWith(".test")) {
		return true;
	}
	if (isPrivateIpv4(host)) return true;
	return false;
}

function isPrivateIpv4(value: string): boolean {
	const parts = value.split(".").map((part) => Number(part));
	if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) return false;
	if (parts[0] === 10) return true;
	if (parts[0] === 127) return true;
	if (parts[0] === 192 && parts[1] === 168) return true;
	if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
	return false;
}

function scoreOpaqueValue(candidate: string, line: string): number | undefined {
	if (looksWordySlug(candidate)) return undefined;
	if (/^[0-9a-f]{40}$/i.test(candidate) && SAFE_GIT_CONTEXT_PATTERN.test(line)) return undefined;
	if (/^[0-9a-f]{64}$/i.test(candidate) && SAFE_HASH_CONTEXT_PATTERN.test(line)) return undefined;
	if (candidate.length >= 24 && SECRET_CONTEXT_PATTERN.test(line)) return 104;
	if (candidate.length >= 32 && shannonEntropy(candidate) >= 3.2) return 86;
	if (candidate.length >= 20 && shannonEntropy(candidate) >= 3.8) return 74;
	return undefined;
}

function looksWordySlug(candidate: string): boolean {
	const segments = candidate.split(/[-_]/).filter(Boolean);
	const alphaSegments = segments.filter((segment) => /^[A-Za-z]{3,}$/.test(segment));
	const letters = [...candidate].filter((char) => /[A-Za-z]/.test(char)).length;
	if (alphaSegments.length < 2 || letters < 8) return false;
	const vowels = [...candidate].filter((char) => /[AEIOUaeiou]/.test(char)).length;
	const vowelRatio = letters > 0 ? vowels / letters : 0;
	return vowelRatio >= 0.25 && vowelRatio <= 0.6;
}

function shannonEntropy(input: string): number {
	const frequencies = new Map<string, number>();
	for (const char of input) {
		frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
	}
	return [...frequencies.values()].reduce((sum, count) => {
		const probability = count / input.length;
		return sum - probability * Math.log2(probability);
	}, 0);
}

function isRecord(value: unknown): value is JsonRecord {
	return typeof value === "object" && value !== null;
}
