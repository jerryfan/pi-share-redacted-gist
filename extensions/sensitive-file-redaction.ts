import type { RedactionStat } from "./redaction";

export type SensitiveFileRedactionOptions = {
	enabled?: boolean;
	extraPatterns?: string[];
};

type SensitiveFileMatcher = string | RegExp;
type JsonRecord = Record<string, unknown>;
type RedactionContext = {
	matchers: SensitiveFileMatcher[];
	sensitiveToolCallIds: Set<string>;
	stats: Map<string, number>;
};

const REDACTED_SENSITIVE_FILE_CONTENT = "[REDACTED_SENSITIVE_FILE_CONTENT]";
const SENSITIVE_FILE_TOOL_NAMES = new Set(["read", "write", "edit"]);
const SENSITIVE_BASH_READ_COMMANDS = new Set(["cat", "bat", "batcat", "less", "more", "head", "tail", "sed", "awk", "grep", "rg"]);
const DEFAULT_SENSITIVE_FILE_MATCHERS: SensitiveFileMatcher[] = [
	/^\.env(?:\.[^/]+)?$/i,
	".envrc",
	".npmrc",
	".yarnrc",
	".yarnrc.yml",
	".pypirc",
	".netrc",
	".git-credentials",
	".bashrc",
	".bash_profile",
	".bash_history",
	".zshrc",
	".zprofile",
	".zsh_history",
	/(?:^|\/)\.ssh\/id_[^/]+$/i,
	/(?:^|\/)\.ssh\/config$/i,
	/\.pem$/i,
	/\.key$/i,
	/(?:^|\/)\.aws\/(?:credentials|config)$/i,
	/(?:^|\/)\.docker\/config\.json$/i,
	/(?:^|\/)\.kube\/config$/i,
	/^credentials\.yml\.enc$/i,
	/^master\.key$/i,
	/^database\.yml$/i,
	/^secrets\.(?:yml|yaml|json)$/i,
	/^(?:service-account|gcp|firebase)[^/]*\.json$/i,
];

export function redactSensitiveFileToolPayloads(text: string, options: SensitiveFileRedactionOptions = {}): { text: string; stats: RedactionStat[] } {
	if (options.enabled === false || !text.trim()) {
		return { text, stats: [] };
	}

	const context: RedactionContext = {
		matchers: [...DEFAULT_SENSITIVE_FILE_MATCHERS, ...compileExtraMatchers(options.extraPatterns ?? [])],
		sensitiveToolCallIds: new Set(),
		stats: new Map(),
	};
	const newline = text.includes("\r\n") ? "\r\n" : "\n";
	const redactedText = text
		.split(/\r?\n/)
		.map((line) => redactLine(line, context))
		.join(newline);

	return {
		text: redactedText,
		stats: [...context.stats.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([label, count]) => ({ label, count })),
	};
}

function redactLine(line: string, context: RedactionContext): string {
	if (!line.trim()) return line;

	let parsed: unknown;
	try {
		parsed = JSON.parse(line);
	} catch {
		return line;
	}
	if (!isRecord(parsed) || parsed.type !== "message" || !isRecord(parsed.message)) return line;

	const message = parsed.message;
	const role = typeof message.role === "string" ? message.role : undefined;
	if (role === "assistant") {
		const updated = redactAssistantMessage(message, context);
		if (updated !== message) return JSON.stringify({ ...parsed, message: updated });
		return line;
	}
	if (role === "toolResult") {
		const updated = redactToolResultMessage(message, context);
		if (updated !== message) return JSON.stringify({ ...parsed, message: updated });
		return line;
	}
	if (role === "bashExecution") {
		const updated = redactBashExecutionMessage(message, context);
		if (updated !== message) return JSON.stringify({ ...parsed, message: updated });
	}
	return line;
}

function redactAssistantMessage(message: JsonRecord, context: RedactionContext): JsonRecord {
	const content = Array.isArray(message.content) ? message.content : undefined;
	if (!content) return message;

	let changed = false;
	const nextContent = content.map((entry) => {
		if (!isRecord(entry) || entry.type !== "toolCall") return entry;
		const toolName = normalizeToolName(entry.name);
		if (!toolName) return entry;

		if (SENSITIVE_FILE_TOOL_NAMES.has(toolName)) {
			const filePath = extractToolPath(entry.arguments);
			if (!filePath || !matchesSensitiveFilePath(filePath, context.matchers)) return entry;
			markSensitiveToolCall(entry.id, context, "sensitive_file_tool_call");
			const updatedEntry = redactToolCallEntry(entry, toolName);
			if (updatedEntry !== entry) changed = true;
			return updatedEntry;
		}

		if (toolName === "bash") {
			const command = extractBashCommand(entry.arguments);
			if (!command || !isSensitiveBashCommand(command, context.matchers)) return entry;
			markSensitiveToolCall(entry.id, context, "sensitive_file_bash_command");
		}
		return entry;
	});

	if (!changed) return message;
	return { ...message, content: nextContent };
}

function redactToolCallEntry(entry: JsonRecord, toolName: string): JsonRecord {
	if (!isRecord(entry.arguments)) return entry;
	if (toolName === "write") {
		if (!("content" in entry.arguments)) return entry;
		return {
			...entry,
			arguments: {
				...entry.arguments,
				content: REDACTED_SENSITIVE_FILE_CONTENT,
			},
		};
	}
	if (toolName === "edit") {
		const nextArguments = redactEditArguments(entry.arguments);
		if (nextArguments === entry.arguments) return entry;
		return {
			...entry,
			arguments: nextArguments,
		};
	}
	return entry;
}

function redactEditArguments(argumentsValue: JsonRecord): JsonRecord {
	let changed = false;
	const nextArguments: JsonRecord = { ...argumentsValue };

	if (typeof argumentsValue.oldText === "string") {
		nextArguments.oldText = REDACTED_SENSITIVE_FILE_CONTENT;
		changed = true;
	}
	if (typeof argumentsValue.newText === "string") {
		nextArguments.newText = REDACTED_SENSITIVE_FILE_CONTENT;
		changed = true;
	}
	if (Array.isArray(argumentsValue.edits)) {
		const nextEdits = argumentsValue.edits.map((entry) => {
			if (!isRecord(entry)) return entry;
			let editChanged = false;
			const nextEdit: JsonRecord = { ...entry };
			if (typeof entry.oldText === "string") {
				nextEdit.oldText = REDACTED_SENSITIVE_FILE_CONTENT;
				editChanged = true;
			}
			if (typeof entry.newText === "string") {
				nextEdit.newText = REDACTED_SENSITIVE_FILE_CONTENT;
				editChanged = true;
			}
			if (editChanged) changed = true;
			return editChanged ? nextEdit : entry;
		});
		nextArguments.edits = nextEdits;
	}

	return changed ? nextArguments : argumentsValue;
}

function redactToolResultMessage(message: JsonRecord, context: RedactionContext): JsonRecord {
	const toolCallId = typeof message.toolCallId === "string" ? message.toolCallId : undefined;
	if (toolCallId && context.sensitiveToolCallIds.has(toolCallId)) {
		incrementStat(context.stats, "sensitive_file_tool_result");
		return redactMessagePayload(message);
	}

	if (normalizeToolName(message.toolName) === "bash") {
		const command = extractBashCommand(message.details) ?? extractBashCommand(message);
		if (command && isSensitiveBashCommand(command, context.matchers)) {
			incrementStat(context.stats, "sensitive_file_bash_output");
			return redactMessagePayload(message);
		}
	}

	return message;
}

function redactBashExecutionMessage(message: JsonRecord, context: RedactionContext): JsonRecord {
	const command = typeof message.command === "string" ? message.command : undefined;
	if (!command || !isSensitiveBashCommand(command, context.matchers)) return message;
	incrementStat(context.stats, "sensitive_file_bash_output");

	return {
		...message,
		output: typeof message.output === "string" ? REDACTED_SENSITIVE_FILE_CONTENT : message.output,
	};
}

function redactMessagePayload(message: JsonRecord): JsonRecord {
	const nextMessage: JsonRecord = { ...message };
	if ("content" in message) nextMessage.content = redactResultValue(message.content, true);
	if ("details" in message) nextMessage.details = redactResultValue(message.details, false);
	if (typeof message.output === "string") nextMessage.output = REDACTED_SENSITIVE_FILE_CONTENT;
	return nextMessage;
}

function redactResultValue(value: unknown, preserveTypeField: boolean): unknown {
	if (typeof value === "string") return REDACTED_SENSITIVE_FILE_CONTENT;
	if (Array.isArray(value)) return value.map((entry) => redactResultValue(entry, preserveTypeField));
	if (!isRecord(value)) return value;

	const output: JsonRecord = {};
	for (const [key, entry] of Object.entries(value)) {
		if (preserveTypeField && key === "type" && typeof entry === "string") {
			output[key] = entry;
			continue;
		}
		output[key] = redactResultValue(entry, preserveTypeField);
	}
	return output;
}

function extractToolPath(value: unknown): string | undefined {
	if (!isRecord(value)) return undefined;
	const pathValue = value.path;
	return typeof pathValue === "string" ? pathValue : undefined;
}

function extractBashCommand(value: unknown): string | undefined {
	if (typeof value === "string") return value;
	if (!isRecord(value)) return undefined;
	const commandValue = value.command;
	return typeof commandValue === "string" ? commandValue : undefined;
}

function markSensitiveToolCall(toolCallId: unknown, context: RedactionContext, label: string): void {
	if (typeof toolCallId === "string") context.sensitiveToolCallIds.add(toolCallId);
	incrementStat(context.stats, label);
}

function normalizeToolName(value: unknown): string | undefined {
	return typeof value === "string" ? value.trim().toLowerCase() : undefined;
}

function isSensitiveBashCommand(command: string, matchers: readonly SensitiveFileMatcher[]): boolean {
	const tokens = tokenizeShellLike(command);
	if (tokens.length === 0) return false;

	const commandNames = tokens
		.map((token) => stripLeadingEnvAssignments(token))
		.filter(Boolean)
		.map((token) => normalizeExecutableName(token));
	const usesReadCommand = commandNames.some((token) => SENSITIVE_BASH_READ_COMMANDS.has(token));
	const referencedSensitivePath = tokens.some((token) => matchesSensitiveFilePath(normalizeShellPathToken(token), matchers));
	if (usesReadCommand && referencedSensitivePath) return true;

	for (let index = 0; index < tokens.length - 1; index++) {
		if (tokens[index] !== "<") continue;
		if (matchesSensitiveFilePath(normalizeShellPathToken(tokens[index + 1] ?? ""), matchers)) return true;
	}
	return false;
}

function tokenizeShellLike(command: string): string[] {
	return command
		.split(/\s+/)
		.map((token) => token.trim())
		.filter(Boolean)
		.flatMap((token) => token.split(/(?=[|;&<>])|(?<=[|;&<>])/))
		.map((token) => token.trim())
		.filter(Boolean);
}

function stripLeadingEnvAssignments(token: string): string {
	if (/^[A-Za-z_][A-Za-z0-9_]*=.*/.test(token)) return "";
	return token;
}

function normalizeExecutableName(token: string): string {
	const normalized = normalizeShellPathToken(token).toLowerCase();
	const basename = normalized.split("/").pop() ?? normalized;
	return basename.replace(/\.(?:exe|cmd|bat|sh)$/i, "");
}

function normalizeShellPathToken(token: string): string {
	return token.replace(/^["'`]+|["'`,:;`]+$/g, "");
}

function matchesSensitiveFilePath(filePath: string, matchers: readonly SensitiveFileMatcher[]): boolean {
	if (!filePath) return false;
	const normalizedPath = normalizePath(filePath);
	const fileName = normalizedPath.split("/").pop() ?? normalizedPath;
	return matchers.some((matcher) => {
		if (typeof matcher === "string") {
			const normalizedMatcher = normalizePath(matcher);
			return fileName === normalizedMatcher || normalizedPath === normalizedMatcher || normalizedPath.endsWith(`/${normalizedMatcher}`);
		}
		matcher.lastIndex = 0;
		if (matcher.test(fileName)) return true;
		matcher.lastIndex = 0;
		return matcher.test(normalizedPath);
	});
}

function compileExtraMatchers(patterns: readonly string[]): SensitiveFileMatcher[] {
	return patterns
		.map((pattern) => parseExtraMatcher(pattern))
		.filter((pattern): pattern is SensitiveFileMatcher => pattern !== undefined);
}

function parseExtraMatcher(value: string): SensitiveFileMatcher | undefined {
	const trimmed = value.trim();
	if (!trimmed) return undefined;
	const regexMatch = trimmed.match(/^\/(.*)\/([a-z]*)$/i);
	if (regexMatch) {
		try {
			return new RegExp(regexMatch[1] ?? "", regexMatch[2] ?? "");
		} catch {
			return undefined;
		}
	}
	return trimmed;
}

function normalizePath(value: string): string {
	return value.replace(/\\/g, "/").replace(/\/+/g, "/");
}

function incrementStat(stats: Map<string, number>, label: string): void {
	stats.set(label, (stats.get(label) ?? 0) + 1);
}

function isRecord(value: unknown): value is JsonRecord {
	return typeof value === "object" && value !== null;
}
