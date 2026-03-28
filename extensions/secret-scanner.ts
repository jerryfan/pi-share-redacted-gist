export type SecretFinding = {
	pluginName: string;
	secretType: string;
	label: string;
	value: string;
	start: number;
	end: number;
	placeholder: string;
	score: number;
	reason: string;
};

export type SecretPluginConfig = {
	name: string;
	options?: Record<string, unknown>;
};

export type SecretScanOptions = {
	plugins?: readonly SecretDetectorPlugin[];
};

export type SecretScanContext = {
	text: string;
};

export interface SecretDetectorPlugin {
	readonly name: string;
	readonly secretType: string;
	analyzeString(text: string, context: SecretScanContext): SecretFinding[];
	json(): SecretPluginConfig;
}

const KEYWORD_PATTERN =
	/\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth(?:orization)?|bearer|client[_-]?secret|cookie|credential|passwd|password|private[_-]?key|secret|session|token)\b/i;
const SECRET_ASSIGNMENT_PATTERN = /\b([A-Za-z][A-Za-z0-9_-]{1,40})\b\s*[:=]\s*("[^"]+"|'[^']+'|`[^`]+`|[^\s,;\]}]+)/g;
const REDACTED_PATTERN = /^\[REDACTED_[A-Z0-9_]+\]$/;
const UUID_CANDIDATE_PATTERN = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$/i;
const SAFE_GIT_CONTEXT_PATTERN = /\b(?:commit|revision|sha|parent|tree|oid)\b/i;
const SAFE_HASH_CONTEXT_PATTERN = /\b(?:sha256|checksum|digest|integrity|hash)\b/i;
const SUSPICIOUS_CONTEXT_PATTERN = /\b(?:token|secret|api[_-]?key|auth|authorization|bearer|cookie|session|password|passwd|signature)\b/i;

export const DEFAULT_SECRET_PLUGIN_CONFIGS: SecretPluginConfig[] = [
	{ name: "PrivateKeyDetector" },
	{ name: "GitHubTokenDetector" },
	{ name: "AwsKeyDetector" },
	{ name: "OpenAIDetector" },
	{ name: "GoogleApiKeyDetector" },
	{ name: "SlackTokenDetector" },
	{ name: "JwtDetector" },
	{ name: "BearerTokenDetector" },
	{ name: "KeywordDetector" },
	{ name: "HexHighEntropyString", options: { limit: 3.0 } },
	{ name: "Base64HighEntropyString", options: { limit: 4.2 } },
	{ name: "OpaqueTokenDetector", options: { limit: 3.6 } },
];

export function initializeSecretPlugins(configs: readonly SecretPluginConfig[] = DEFAULT_SECRET_PLUGIN_CONFIGS): SecretDetectorPlugin[] {
	return configs.map((config) => createSecretPlugin(config));
}

export function scanSecrets(text: string, options: SecretScanOptions = {}): SecretFinding[] {
	if (!text) return [];
	const plugins = options.plugins ?? DEFAULT_SECRET_PLUGINS;
	const context: SecretScanContext = { text };
	const findings = plugins.flatMap((plugin) => plugin.analyzeString(text, context));
	return resolveOverlaps(findings);
}

export abstract class BaseSecretPlugin implements SecretDetectorPlugin {
	abstract readonly name: string;
	abstract readonly secretType: string;
	protected readonly defaultPlaceholder = "[REDACTED_SECRET]";

	abstract analyzeString(text: string, context: SecretScanContext): SecretFinding[];

	json(): SecretPluginConfig {
		return { name: this.name };
	}

	protected buildFinding(args: Omit<SecretFinding, "pluginName" | "secretType">): SecretFinding {
		return {
			pluginName: this.name,
			secretType: this.secretType,
			...args,
		};
	}
}

export abstract class RegexBasedSecretPlugin extends BaseSecretPlugin {
	protected abstract readonly denylist: readonly RegExp[];

	analyzeString(text: string): SecretFinding[] {
		const findings: SecretFinding[] = [];
		for (const pattern of this.denylist) {
			for (const match of text.matchAll(globalize(pattern))) {
				const fullMatch = match[0] ?? "";
				const value = this.extractValue(match);
				if (!value || !looksSensitiveSecretValue(value)) continue;
				const relativeOffset = Math.max(0, fullMatch.indexOf(value));
				const start = (match.index ?? 0) + relativeOffset;
				const end = start + value.length;
				if (!this.shouldKeep(value, text, match)) continue;
				findings.push(
					this.buildFinding({
						label: this.labelFor(value),
						value,
						start,
						end,
						placeholder: this.placeholderFor(value),
						score: this.scoreFor(value, text),
						reason: this.reasonFor(value),
					}),
				);
			}
		}
		return findings;
	}

	protected extractValue(match: RegExpMatchArray): string {
		return match[0] ?? "";
	}

	protected shouldKeep(_value: string, _text: string, _match: RegExpMatchArray): boolean {
		return true;
	}

	protected labelFor(_value: string): string {
		return humanizeSecretType(this.secretType);
	}

	protected placeholderFor(_value: string): string {
		return this.defaultPlaceholder;
	}

	protected scoreFor(_value: string, _text: string): number {
		return 120;
	}

	protected reasonFor(_value: string): string {
		return `${humanizeSecretType(this.secretType)} matched ${this.name}`;
	}
}

class KeywordDetector extends BaseSecretPlugin {
	readonly name = "KeywordDetector";
	readonly secretType = "keyword_secret";

	analyzeString(text: string): SecretFinding[] {
		const findings: SecretFinding[] = [];
		for (const match of text.matchAll(SECRET_ASSIGNMENT_PATTERN)) {
			const key = match[1] ?? "value";
			if (!KEYWORD_PATTERN.test(key)) continue;
			const rawValue = trimWrappedValue(match[2] ?? "");
			if (!looksSensitiveSecretValue(rawValue)) continue;
			const fullMatch = match[0] ?? "";
			const valueOffset = fullMatch.indexOf(rawValue);
			const start = (match.index ?? 0) + Math.max(0, valueOffset);
			findings.push(
				this.buildFinding({
					label: "Keyword secret",
					value: rawValue,
					start,
					end: start + rawValue.length,
					placeholder: this.defaultPlaceholder,
					score: 132,
					reason: `Sensitive-looking value assigned to ${key}`,
				}),
			);
		}
		return findings;
	}
}

abstract class HighEntropyStringPlugin extends BaseSecretPlugin {
	protected abstract readonly candidatePattern: RegExp;
	protected abstract readonly limit: number;
	protected abstract readonly minimumLength: number;

	analyzeString(text: string): SecretFinding[] {
		const findings: SecretFinding[] = [];
		for (const match of text.matchAll(globalize(this.candidatePattern))) {
			const value = match[0] ?? "";
			if (!looksSensitiveSecretValue(value)) continue;
			if (!this.isCandidate(value, text, match.index ?? 0)) continue;
			const suspiciousContext = contextLooksSensitive(text, match.index ?? 0, value.length);
			findings.push(
				this.buildFinding({
					label: this.labelFor(value),
					value,
					start: match.index ?? 0,
					end: (match.index ?? 0) + value.length,
					placeholder: this.placeholderFor(value),
					score: this.scoreFor(value, suspiciousContext),
					reason: this.reasonFor(value),
				}),
			);
		}
		return findings;
	}

	json(): SecretPluginConfig {
		return { name: this.name, options: { limit: this.limit } };
	}

	protected labelFor(_value: string): string {
		return humanizeSecretType(this.secretType);
	}

	protected scoreFor(_value: string, suspiciousContext: boolean): number {
		return suspiciousContext ? 116 : 90;
	}

	protected reasonFor(_value: string): string {
		return `High-entropy value matched ${this.name}`;
	}

	protected abstract isCandidate(value: string, text: string, start: number): boolean;
}

class HexHighEntropyString extends HighEntropyStringPlugin {
	readonly name = "HexHighEntropyString";
	readonly secretType = "opaque_hex";
	protected readonly candidatePattern = /\b[0-9a-f]{16,}\b/gi;
	protected readonly minimumLength = 32;

	constructor(protected readonly limit = 3.0) {
		super();
	}

	protected placeholderFor(): string {
		return "[REDACTED_OPAQUE_HEX]";
	}

	protected isCandidate(value: string, text: string, start: number): boolean {
		if (!/^[0-9a-f]+$/i.test(value)) return false;
		if (UUID_CANDIDATE_PATTERN.test(value)) return false;
		const suspiciousContext = contextLooksSensitive(text, start, value.length);
		const minLength = suspiciousContext ? 24 : this.minimumLength;
		const minLimit = suspiciousContext ? Math.max(2.7, this.limit - 0.3) : this.limit;
		if (value.length < minLength) return false;
		if (isLikelySafeHash(value, sliceSurroundings(text, start, value.length))) return false;
		return shannonEntropy(value) >= minLimit;
	}
}

class Base64HighEntropyString extends HighEntropyStringPlugin {
	readonly name = "Base64HighEntropyString";
	readonly secretType = "opaque_base64";
	protected readonly candidatePattern = /[-A-Za-z0-9+_]{16,}={0,2}/g;
	protected readonly minimumLength = 24;

	constructor(protected readonly limit = 4.2) {
		super();
	}

	protected placeholderFor(): string {
		return "[REDACTED_OPAQUE_BASE64]";
	}

	protected isCandidate(value: string, text: string, start: number): boolean {
		if (!/^[A-Za-z0-9+_-]+={0,2}$/.test(value)) return false;
		const suspiciousContext = contextLooksSensitive(text, start, value.length);
		const minLength = suspiciousContext ? 16 : this.minimumLength;
		const minSignals = suspiciousContext ? 1 : 2;
		const minLimit = suspiciousContext ? Math.max(3.8, this.limit - 0.4) : this.limit;
		if (value.length < minLength) return false;
		if (signalCount(value) < minSignals) return false;
		return shannonEntropy(value) >= minLimit;
	}
}

class OpaqueTokenDetector extends HighEntropyStringPlugin {
	readonly name = "OpaqueTokenDetector";
	readonly secretType = "opaque";
	protected readonly candidatePattern = /[-A-Za-z0-9_]{20,}/g;
	protected readonly minimumLength = 20;

	constructor(protected readonly limit = 3.6) {
		super();
	}

	protected placeholderFor(): string {
		return "[REDACTED_OPAQUE]";
	}

	protected isCandidate(value: string, text: string, start: number): boolean {
		if (!/^[-A-Za-z0-9_]+$/.test(value)) return false;
		const suspiciousContext = contextLooksSensitive(text, start, value.length);
		const minLength = suspiciousContext ? 16 : this.minimumLength;
		const minClasses = suspiciousContext ? 2 : 3;
		const minLimit = suspiciousContext ? Math.max(3.2, this.limit - 0.4) : this.limit;
		if (value.length < minLength) return false;
		if (characterClassCount(value) < minClasses) return false;
		return shannonEntropy(value) >= minLimit;
	}
}

class PrivateKeyDetector extends RegexBasedSecretPlugin {
	readonly name = "PrivateKeyDetector";
	readonly secretType = "private_key";
	protected readonly denylist = [
		/-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
		/-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
	] as const;

	protected placeholderFor(): string {
		return "[REDACTED_PRIVATE_KEY]";
	}

	protected scoreFor(): number {
		return 180;
	}
}

class GitHubTokenDetector extends RegexBasedSecretPlugin {
	readonly name = "GitHubTokenDetector";
	readonly secretType = "github_token";
	protected readonly denylist = [/\b(?:gh[opusr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,})\b/g] as const;

	protected placeholderFor(): string {
		return "[REDACTED_TOKEN]";
	}

	protected scoreFor(): number {
		return 158;
	}
}

class AwsKeyDetector extends RegexBasedSecretPlugin {
	readonly name = "AwsKeyDetector";
	readonly secretType = "aws_key";
	protected readonly denylist = [/\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g] as const;

	protected scoreFor(): number {
		return 152;
	}
}

class OpenAIDetector extends RegexBasedSecretPlugin {
	readonly name = "OpenAIDetector";
	readonly secretType = "openai_key";
	protected readonly denylist = [/\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g] as const;

	protected scoreFor(): number {
		return 154;
	}
}

class GoogleApiKeyDetector extends RegexBasedSecretPlugin {
	readonly name = "GoogleApiKeyDetector";
	readonly secretType = "google_api_key";
	protected readonly denylist = [/\bAIza[0-9A-Za-z_-]{35}\b/g] as const;

	protected scoreFor(): number {
		return 150;
	}
}

class SlackTokenDetector extends RegexBasedSecretPlugin {
	readonly name = "SlackTokenDetector";
	readonly secretType = "slack_token";
	protected readonly denylist = [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g] as const;

	protected scoreFor(): number {
		return 150;
	}
}

class JwtDetector extends RegexBasedSecretPlugin {
	readonly name = "JwtDetector";
	readonly secretType = "jwt";
	protected readonly denylist = [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g] as const;

	protected placeholderFor(): string {
		return "[REDACTED_JWT]";
	}

	protected scoreFor(): number {
		return 148;
	}
}

class BearerTokenDetector extends RegexBasedSecretPlugin {
	readonly name = "BearerTokenDetector";
	readonly secretType = "bearer_token";
	protected readonly denylist = [/\bBearer\s+([A-Za-z0-9._~+/-]{8,})/g] as const;

	protected extractValue(match: RegExpMatchArray): string {
		return match[1] ?? "";
	}

	protected scoreFor(): number {
		return 156;
	}
}

const BUILTIN_PLUGIN_FACTORIES: Record<string, (options?: Record<string, unknown>) => SecretDetectorPlugin> = {
	KeywordDetector: () => new KeywordDetector(),
	Base64HighEntropyString: (options) => new Base64HighEntropyString(numberOption(options, "limit", 4.2)),
	HexHighEntropyString: (options) => new HexHighEntropyString(numberOption(options, "limit", 3.0)),
	OpaqueTokenDetector: (options) => new OpaqueTokenDetector(numberOption(options, "limit", 3.6)),
	PrivateKeyDetector: () => new PrivateKeyDetector(),
	GitHubTokenDetector: () => new GitHubTokenDetector(),
	AwsKeyDetector: () => new AwsKeyDetector(),
	OpenAIDetector: () => new OpenAIDetector(),
	GoogleApiKeyDetector: () => new GoogleApiKeyDetector(),
	SlackTokenDetector: () => new SlackTokenDetector(),
	JwtDetector: () => new JwtDetector(),
	BearerTokenDetector: () => new BearerTokenDetector(),
};

const DEFAULT_SECRET_PLUGINS = initializeSecretPlugins();

function createSecretPlugin(config: SecretPluginConfig): SecretDetectorPlugin {
	const factory = BUILTIN_PLUGIN_FACTORIES[config.name];
	if (!factory) throw new Error(`Unknown secret plugin: ${config.name}`);
	return factory(config.options);
}

function resolveOverlaps(findings: readonly SecretFinding[]): SecretFinding[] {
	const accepted: SecretFinding[] = [];
	for (const finding of [...findings].sort((a, b) => b.score - a.score || (b.end - b.start) - (a.end - a.start) || a.start - b.start)) {
		if (accepted.some((entry) => overlaps(entry, finding))) continue;
		accepted.push(finding);
	}
	return accepted.sort((a, b) => a.start - b.start || b.score - a.score);
}

function overlaps(left: SecretFinding, right: SecretFinding): boolean {
	return left.start < right.end && right.start < left.end;
}

function humanizeSecretType(secretType: string): string {
	return secretType
		.split("_")
		.map((part) => part.charAt(0).toUpperCase() + part.slice(1))
		.join(" ");
}

function trimWrappedValue(value: string): string {
	const trimmed = value.trim();
	if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'")) || (trimmed.startsWith("`") && trimmed.endsWith("`"))) {
		return trimmed.slice(1, -1);
	}
	return trimmed;
}

function looksSensitiveSecretValue(value: string): boolean {
	if (!value || value.length < 4) return false;
	if (REDACTED_PATTERN.test(value)) return false;
	if (/^(?:true|false|null|undefined)$/i.test(value)) return false;
	if (/^(?:yes|no|ok|none|error)$/i.test(value)) return false;
	if (/^\d+(?:-\d+)?$/.test(value)) return false;
	if (looksWordySlug(value)) return false;
	return true;
}

function contextLooksSensitive(text: string, start: number, length: number): boolean {
	return SUSPICIOUS_CONTEXT_PATTERN.test(sliceSurroundings(text, start, length));
}

function sliceSurroundings(text: string, start: number, length: number): string {
	const before = text.slice(Math.max(0, start - 48), start);
	const after = text.slice(start + length, start + length + 48);
	return `${before} ${after}`;
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

function numberOption(options: Record<string, unknown> | undefined, key: string, fallback: number): number {
	const value = options?.[key];
	return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function globalize(pattern: RegExp): RegExp {
	const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
	return new RegExp(pattern.source, flags);
}
