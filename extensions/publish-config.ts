import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { getAgentDir } from "@mariozechner/pi-coding-agent";

export type GistPublisherConfig = {
	enabled?: boolean;
	description?: string;
};

export type HuggingFacePublisherConfig = {
	enabled?: boolean;
	datasets?: string[];
	defaultDataset?: string;
	visibility?: "public" | "private";
	pathPrefix?: string;
};

export type SensitiveFilesRedactionConfig = {
	enabled?: boolean;
	extraPatterns?: string[];
};

export type PublishConfig = {
	publishers?: {
		gist?: GistPublisherConfig;
		huggingface?: HuggingFacePublisherConfig;
	};
	redaction?: {
		sensitiveFiles?: SensitiveFilesRedactionConfig;
	};
};

export type LoadedPublishConfig = {
	config: PublishConfig;
	loadedPaths: string[];
	warnings: string[];
	globalPath: string;
	projectPath: string;
};

const CONFIG_FILENAME = "pi-share-redacted-gist.json";

export function loadPublishConfig(cwd: string): LoadedPublishConfig {
	const globalPath = path.join(getAgentDir(), CONFIG_FILENAME);
	const projectPath = path.join(cwd, ".pi", CONFIG_FILENAME);
	const warnings: string[] = [];
	const loadedPaths: string[] = [];

	const globalConfig = readConfigFile(globalPath, warnings, loadedPaths);
	const projectConfig = readConfigFile(projectPath, warnings, loadedPaths);

	return {
		config: mergePublishConfig(globalConfig, projectConfig),
		loadedPaths,
		warnings,
		globalPath,
		projectPath,
	};
}

export function getConfiguredDatasets(config: PublishConfig): string[] {
	const raw = config.publishers?.huggingface?.datasets ?? [];
	return [...new Set(raw.map((entry) => entry.trim()).filter(Boolean))];
}

function readConfigFile(pathname: string, warnings: string[], loadedPaths: string[]): PublishConfig {
	if (!existsSync(pathname)) return {};
	try {
		const parsed = JSON.parse(readFileSync(pathname, "utf8")) as unknown;
		if (!isRecord(parsed)) {
			warnings.push(`Ignoring ${pathname}: expected JSON object`);
			return {};
		}
		loadedPaths.push(pathname);
		return parsed as PublishConfig;
	} catch (error) {
		warnings.push(`Failed reading ${pathname}: ${toErrorMessage(error)}`);
		return {};
	}
}

function mergePublishConfig(globalConfig: PublishConfig, projectConfig: PublishConfig): PublishConfig {
	const globalPublishers = globalConfig.publishers;
	const projectPublishers = projectConfig.publishers;
	const globalSensitiveFiles = globalConfig.redaction?.sensitiveFiles;
	const projectSensitiveFiles = projectConfig.redaction?.sensitiveFiles;
	if (!globalPublishers && !projectPublishers && !globalSensitiveFiles && !projectSensitiveFiles) return {};

	return {
		publishers: {
			gist: {
				...globalPublishers?.gist,
				...projectPublishers?.gist,
			},
			huggingface: {
				...globalPublishers?.huggingface,
				...projectPublishers?.huggingface,
				datasets: projectPublishers?.huggingface?.datasets ?? globalPublishers?.huggingface?.datasets,
			},
		},
		redaction: {
			sensitiveFiles: {
				...globalConfig.redaction?.sensitiveFiles,
				...projectConfig.redaction?.sensitiveFiles,
				extraPatterns: mergeStringLists(globalConfig.redaction?.sensitiveFiles?.extraPatterns, projectConfig.redaction?.sensitiveFiles?.extraPatterns),
			},
		},
	};
}

function mergeStringLists(globalValues: string[] | undefined, projectValues: string[] | undefined): string[] | undefined {
	const merged = [...(globalValues ?? []), ...(projectValues ?? [])].map((entry) => entry.trim()).filter(Boolean);
	if (merged.length === 0) return undefined;
	return [...new Set(merged)];
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) return error.message;
	return String(error);
}
