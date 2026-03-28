import { existsSync, readFileSync } from "node:fs";
import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";

import { getAgentDir } from "@mariozechner/pi-coding-agent";

const execFileAsync = promisify(execFile);

export type ResolvedConfiguredSecret = {
	value?: string;
	source?: string;
	error?: string;
};

export type ResolvedHuggingFaceAccessToken = {
	token?: string;
	source?: string;
	authPath: string;
	error?: string;
};

export async function resolveHuggingFaceAccessToken(): Promise<ResolvedHuggingFaceAccessToken> {
	const authPath = path.join(getAgentDir(), "auth.json");
	const envToken = process.env.HF_TOKEN?.trim();
	if (envToken) {
		return { token: envToken, source: "HF_TOKEN", authPath };
	}

	if (!existsSync(authPath)) return { authPath };

	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(authPath, "utf8"));
	} catch (error) {
		return { authPath, error: `Failed reading ${authPath}: ${toErrorMessage(error)}` };
	}

	if (!isRecord(parsed)) {
		return { authPath, error: `Invalid auth file: ${authPath}` };
	}

	const authEntry = parsed.huggingface;
	if (!isRecord(authEntry)) return { authPath };
	if (authEntry.type !== undefined && authEntry.type !== "api_key") {
		return { authPath, error: `Unsupported huggingface auth entry type: ${String(authEntry.type)}` };
	}
	if (typeof authEntry.key !== "string") {
		return { authPath, error: `Invalid huggingface auth entry in ${authPath}: missing string key` };
	}

	const resolved = await resolveConfiguredSecretValue(authEntry.key);
	if (!resolved.value) {
		return { authPath, error: resolved.error ?? `Could not resolve huggingface token from ${authPath}` };
	}

	return {
		token: resolved.value,
		source: `${authPath} → huggingface${resolved.source ? ` (${resolved.source})` : ""}`,
		authPath,
	};
}

export async function resolveConfiguredSecretValue(rawValue: string): Promise<ResolvedConfiguredSecret> {
	const value = rawValue.trim();
	if (!value) return { error: "Secret value is empty" };
	if (value.startsWith("!")) {
		const command = value.slice(1).trim();
		if (!command) return { error: "Shell command secret value is empty" };
		try {
			const { stdout } = await execFileAsync("/bin/bash", ["-lc", command], { maxBuffer: 1024 * 1024 });
			const output = stdout.trim();
			if (!output) return { error: `Secret command produced no output: ${command}` };
			return { value: output, source: `shell:${command}` };
		} catch (error) {
			return { error: `Secret command failed: ${toErrorMessage(error)}` };
		}
	}
	if (looksLikeEnvVarName(value)) {
		const envValue = process.env[value]?.trim();
		if (!envValue) return { error: `Environment variable ${value} is not set` };
		return { value: envValue, source: `env:${value}` };
	}
	return { value, source: "literal" };
}

function looksLikeEnvVarName(value: string): boolean {
	return /^[A-Z][A-Z0-9_]*$/.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) return error.message;
	return String(error);
}
