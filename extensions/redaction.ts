import { scanSecrets } from "./secret-scanner";

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
	return redactSecrets(output, context);
}

function redactSecrets(input: string, context: RedactionContext): string {
	const findings = scanSecrets(input);
	if (findings.length === 0) return input;

	let output = input;
	for (const finding of [...findings].sort((a, b) => b.start - a.start || b.score - a.score)) {
		incrementStat(context.stats, finding.secretType);
		output = `${output.slice(0, finding.start)}${finding.placeholder}${output.slice(finding.end)}`;
	}
	return output;
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
		{ label: "uuid", pattern: UUID_RULE_PATTERN, replace: "[REDACTED_UUID]" },
		{ label: "home_path", pattern: /\/home\/[^/\s]+\//g, replace: "/home/[REDACTED_USER]/" },
		{ label: "windows_path", pattern: /[A-Za-z]:\\Users\\[^\\\s]+\\/g, replace: "C:\\Users\\[REDACTED_USER]\\" },
		{ label: "private_url", pattern: /https?:\/\/[^\s"']+\.(?:local|internal|lan|home|arpa|test)\b/gi, replace: "[REDACTED_PRIVATE_URL]" },
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

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
