export type RedactionStat = {
	label: string;
	count: number;
};

export type RedactionOptions = {
	cwd: string;
	homeDir: string;
	usernameCandidates: string[];
};

type RedactionRule = {
	label: string;
	pattern: RegExp;
	replace: string;
};

type RedactionContext = {
	rules: RedactionRule[];
	stats: Map<string, number>;
};

const UUID_RULE_PATTERN = /\b(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})\b/gi;
const UUID_CANDIDATE_PATTERN = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$/i;
const OPAQUE_TOKEN_PATTERN = /[-A-Za-z0-9+_]{16,}={0,2}/g;
const SUSPICIOUS_CONTEXT_PATTERN = /\b(?:token|secret|api[_-]?key|auth|authorization|bearer|cookie|session|password|passwd|signature)\b/i;
const SAFE_GIT_CONTEXT_PATTERN = /\b(?:commit|revision|sha|parent|tree|oid)\b/i;
const SAFE_HASH_CONTEXT_PATTERN = /\b(?:sha256|checksum|digest|integrity|hash)\b/i;

export function redactSensitive(text: string, options: RedactionOptions): { text: string; stats: RedactionStat[] } {
	const stats = new Map<string, number>();
	const context: RedactionContext = {
		rules: buildRules(options),
		stats,
	};
	const newline = text.includes("\r\n") ? "\r\n" : "\n";
	const lines = text.split(/\r?\n/);
	const redactedText = lines.map((line) => redactLine(line, context)).join(newline);
	return {
		text: redactedText,
		stats: [...stats.entries()].map(([label, count]) => ({ label, count })),
	};
}

function redactLine(line: string, context: RedactionContext): string {
	if (!line.trim()) return line;
	try {
		const parsed = JSON.parse(line) as unknown;
		return JSON.stringify(redactValue(parsed, context));
	} catch {
		return redactString(line, context);
	}
}

function redactValue(value: unknown, context: RedactionContext): unknown {
	if (typeof value === "string") return redactString(value, context);
	if (Array.isArray(value)) return value.map((entry) => redactValue(entry, context));
	if (!isRecord(value)) return value;
	return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, redactValue(entry, context)]));
}

function redactString(input: string, context: RedactionContext): string {
	let output = input;
	for (const rule of context.rules) {
		output = output.replace(rule.pattern, () => {
			incrementStat(context.stats, rule.label);
			return rule.replace;
		});
	}
	return redactOpaqueTokens(output, context);
}

function redactOpaqueTokens(input: string, context: RedactionContext): string {
	return input.replace(OPAQUE_TOKEN_PATTERN, (candidate, offset, fullText) => {
		if (candidate.startsWith("REDACTED_")) return candidate;
		const before = fullText.slice(Math.max(0, offset - 48), offset);
		const after = fullText.slice(offset + candidate.length, offset + candidate.length + 48);
		const surroundings = `${before} ${after}`;
		const replacement = classifyOpaqueCandidate(candidate, surroundings);
		if (!replacement) return candidate;
		incrementStat(context.stats, replacement.label);
		return replacement.placeholder;
	});
}

function classifyOpaqueCandidate(candidate: string, surroundings: string): { label: string; placeholder: string } | undefined {
	if (looksWordySlug(candidate)) return undefined;
	const suspiciousContext = SUSPICIOUS_CONTEXT_PATTERN.test(surroundings);

	if (isHexOpaque(candidate, surroundings, suspiciousContext)) {
		return { label: "opaque_hex", placeholder: "[REDACTED_OPAQUE_HEX]" };
	}

	if (isBase64Opaque(candidate, suspiciousContext)) {
		return { label: "opaque_base64", placeholder: "[REDACTED_OPAQUE_BASE64]" };
	}

	if (isMixedOpaque(candidate, suspiciousContext)) {
		return { label: "opaque", placeholder: "[REDACTED_OPAQUE]" };
	}

	return undefined;
}

function isHexOpaque(candidate: string, surroundings: string, suspiciousContext: boolean): boolean {
	if (!/^[0-9a-f]+$/i.test(candidate)) return false;
	if (UUID_CANDIDATE_PATTERN.test(candidate)) return false;
	if (candidate.length < (suspiciousContext ? 24 : 32)) return false;
	if (isLikelySafeHash(candidate, surroundings)) return false;
	return shannonEntropy(candidate) >= (suspiciousContext ? 2.7 : 3.0);
}

function isBase64Opaque(candidate: string, suspiciousContext: boolean): boolean {
	if (!/^[A-Za-z0-9+_-]+={0,2}$/.test(candidate)) return false;
	if (candidate.length < (suspiciousContext ? 16 : 24)) return false;
	if (signalCount(candidate) < (suspiciousContext ? 1 : 2)) return false;
	return shannonEntropy(candidate) >= (suspiciousContext ? 3.8 : 4.2);
}

function isMixedOpaque(candidate: string, suspiciousContext: boolean): boolean {
	if (!/^[-A-Za-z0-9_]+$/.test(candidate)) return false;
	if (candidate.length < (suspiciousContext ? 16 : 20)) return false;
	if (characterClassCount(candidate) < (suspiciousContext ? 2 : 3)) return false;
	return shannonEntropy(candidate) >= (suspiciousContext ? 3.2 : 3.6);
}

function isLikelySafeHash(candidate: string, surroundings: string): boolean {
	if (/^[0-9a-f]{40}$/i.test(candidate) && SAFE_GIT_CONTEXT_PATTERN.test(surroundings)) return true;
	if (/^[0-9a-f]{64}$/i.test(candidate) && SAFE_HASH_CONTEXT_PATTERN.test(surroundings)) return true;
	return false;
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

function signalCount(candidate: string): number {
	let count = 0;
	if (/[A-Z]/.test(candidate) && /[a-z]/.test(candidate)) count += 1;
	if (/\d/.test(candidate)) count += 1;
	if (/[-_+=]/.test(candidate)) count += 1;
	return count;
}

function characterClassCount(candidate: string): number {
	let count = 0;
	if (/[a-z]/.test(candidate)) count += 1;
	if (/[A-Z]/.test(candidate)) count += 1;
	if (/\d/.test(candidate)) count += 1;
	if (/[-_]/.test(candidate)) count += 1;
	return count;
}

function buildRules(options: RedactionOptions): RedactionRule[] {
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
		{ label: "uuid", pattern: UUID_RULE_PATTERN, replace: "[REDACTED_UUID]" },
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
			replace: "[REDACTED_HOME_DIR]",
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
	return rules;
}

function incrementStat(stats: Map<string, number>, label: string): void {
	stats.set(label, (stats.get(label) ?? 0) + 1);
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

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
