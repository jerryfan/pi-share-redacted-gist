import type { ReviewOccurrence } from "./review-model";

export type ManualRedactionRule = {
	id: string;
	type: "literal" | "regex";
	pattern: string;
	flags?: string;
	replace: string;
	label: string;
};

const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const URL_PATTERN = /https?:\/\/[^\s"')\]]+/gi;
const PATH_PATTERN = /(?:\/Users\/[^\s"'`()\[\]{}]+|\/home\/[^\s"'`()\[\]{}]+|[A-Za-z]:\\Users\\[^\\\s"'`()\[\]{}]+(?:\\[^\\\s"'`()\[\]{}]+)*)/g;
const IPV4_PATTERN = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g;
const IPV6_PRIVATE_PATTERN = /\b(?:fd|fc)[0-9a-f:]{6,}\b/gi;

export function applyManualRedactions(text: string, rules: readonly ManualRedactionRule[]): { text: string; replacements: number } {
	let nextText = text;
	let replacements = 0;
	for (const rule of rules) {
		const pattern = createRulePattern(rule);
		const matches = [...nextText.matchAll(pattern)].length;
		if (matches === 0) continue;
		replacements += matches;
		nextText = nextText.replace(pattern, rule.replace);
	}
	return { text: nextText, replacements };
}

export function countRuleMatches(text: string, rule: ManualRedactionRule): number {
	return [...text.matchAll(createRulePattern(rule))].length;
}

export function createLiteralRule(value: string, replace?: string): ManualRedactionRule | Error {
	const trimmed = value.trim();
	if (!trimmed) return new Error("Literal redaction cannot be empty");
	return {
		id: `literal-${hashId(trimmed)}`,
		type: "literal",
		pattern: trimmed,
		replace: replace ?? suggestPlaceholder(trimmed),
		label: `literal:${trimmed}`,
	};
}

export function createRegexRule(input: string, replace?: string): ManualRedactionRule | Error {
	const trimmed = input.trim();
	if (!trimmed) return new Error("Regex redaction cannot be empty");

	let pattern = trimmed;
	let flags = "g";
	const parsed = parseSlashRegex(trimmed);
	if (parsed) {
		pattern = parsed.pattern;
		flags = parsed.flags.includes("g") ? parsed.flags : `${parsed.flags}g`;
	}

	try {
		new RegExp(pattern, flags);
	} catch (error) {
		return error instanceof Error ? error : new Error(String(error));
	}

	return {
		id: `regex-${hashId(`${pattern}/${flags}`)}`,
		type: "regex",
		pattern,
		flags,
		replace: replace ?? "[REDACTED_CUSTOM]",
		label: `regex:/${pattern}/${flags}`,
	};
}

export function createRuleFromOccurrence(entry: ReviewOccurrence): ManualRedactionRule {
	return {
		id: `literal-${hashId(entry.value)}`,
		type: "literal",
		pattern: entry.value,
		replace: entry.suggestedPlaceholder,
		label: `${entry.label}:${entry.value}`,
	};
}

export function summarizeRule(rule: ManualRedactionRule): string {
	return `${rule.label} → ${rule.replace}`;
}

export function suggestPlaceholder(value: string): string {
	if (matchesPattern(EMAIL_PATTERN, value)) return "[REDACTED_EMAIL]";
	if (matchesPattern(PATH_PATTERN, value)) return suggestPathPlaceholder(value);
	if (matchesPattern(URL_PATTERN, value) || isInternalHostname(value)) return "[REDACTED_URL]";
	if (matchesPattern(IPV4_PATTERN, value) || matchesPattern(IPV6_PRIVATE_PATTERN, value)) return "[REDACTED_IP]";
	return "[REDACTED_SECRET]";
}

function suggestPathPlaceholder(value: string): string {
	if (value.startsWith("/Users/")) return "/Users/[REDACTED_USER]";
	if (value.startsWith("/home/")) return "/home/[REDACTED_USER]";
	if (/^[A-Za-z]:\\Users\\/.test(value)) return "C:\\Users\\[REDACTED_USER]";
	return "[REDACTED_PATH]";
}

function matchesPattern(pattern: RegExp, value: string): boolean {
	pattern.lastIndex = 0;
	return pattern.test(value);
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

function createRulePattern(rule: ManualRedactionRule): RegExp {
	if (rule.type === "literal") return new RegExp(escapeRegExp(rule.pattern), "g");
	const flags = rule.flags?.includes("g") ? rule.flags : `${rule.flags ?? ""}g`;
	return new RegExp(rule.pattern, flags);
}

function parseSlashRegex(input: string): { pattern: string; flags: string } | undefined {
	if (!input.startsWith("/")) return undefined;
	let escaped = false;
	for (let i = input.length - 1; i > 0; i--) {
		const char = input[i]!;
		if (char === "/" && !escaped) {
			return {
				pattern: input.slice(1, i),
				flags: input.slice(i + 1),
			};
		}
		escaped = char === "\\" && !escaped;
	}
	return undefined;
}

function hashId(value: string): string {
	let hash = 2166136261;
	for (const char of value) {
		hash ^= char.charCodeAt(0);
		hash = Math.imul(hash, 16777619);
	}
	return Math.abs(hash).toString(16);
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
