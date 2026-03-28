import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

import { createRepo, repoExists, uploadFiles } from "@huggingface/hub";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

export type PublisherChoice = "gist" | "huggingface" | "both";

export type PublicationBundle = {
	sessionPath: string;
	sessionFilename: string;
	sessionText: string;
	metadataText: string;
	createdAt: string;
	description: string;
};

export type PublishResult =
	| {
			publisher: "gist";
			url?: string;
	  }
	| {
			publisher: "huggingface";
			dataset: string;
			repoUrl: string;
			commitUrl?: string;
			treeUrl: string;
			remoteDir: string;
	  };

export type PublishFailure = {
	publisher: Exclude<PublisherChoice, "both">;
	message: string;
};

export async function publishToGist(pi: ExtensionAPI, bundle: PublicationBundle): Promise<PublishResult> {
	const tmpDir = path.join(os.tmpdir(), `pi-openagentsession-${Date.now()}`);
	const sessionOut = path.join(tmpDir, bundle.sessionFilename);
	const metadataOut = path.join(tmpDir, "openagentsessions.json");

	await fs.mkdir(tmpDir, { recursive: true });
	await fs.writeFile(sessionOut, bundle.sessionText, "utf8");
	await fs.writeFile(metadataOut, bundle.metadataText, "utf8");

	const gist = await pi.exec("gh", ["gist", "create", sessionOut, metadataOut, "--public", "--desc", bundle.description]);
	if (gist.code !== 0) {
		throw new Error(gist.stderr.trim() || gist.stdout.trim() || "gh gist create failed");
	}

	return {
		publisher: "gist",
		url: resolvePublishedGistUrl(gist.stdout, gist.stderr),
	};
}

export async function publishToHuggingFace(
	bundle: PublicationBundle,
	options: {
		accessToken: string;
		dataset: string;
		visibility?: "public" | "private";
		pathPrefix?: string;
	},
): Promise<PublishResult> {
	const repo = { type: "dataset" as const, name: options.dataset };
	const repoUrl = await ensureDatasetRepo(repo, options.accessToken, options.visibility);
	const remoteDir = buildRemoteDir(bundle, options.pathPrefix);
	const output = await uploadFiles({
		repo,
		accessToken: options.accessToken,
		commitTitle: `Add redacted session ${path.basename(bundle.sessionPath)}`,
		commitDescription: bundle.description,
		files: [
			{
				path: `${remoteDir}/${bundle.sessionFilename}`,
				content: new Blob([bundle.sessionText]),
			},
			{
				path: `${remoteDir}/openagentsessions.json`,
				content: new Blob([bundle.metadataText]),
			},
		],
	});

	return {
		publisher: "huggingface",
		dataset: options.dataset,
		repoUrl,
		commitUrl: output?.commit.url,
		treeUrl: `${repoUrl}/tree/main/${encodeRepoPath(remoteDir)}`,
		remoteDir,
	};
}

export function buildSubmissionMessage(results: PublishResult[], failures: PublishFailure[] = []): string {
	const submitUrl = "https://openagentsessions.org/submit";
	const gist = results.find((result) => result.publisher === "gist");
	const huggingface = results.find((result) => result.publisher === "huggingface");
	const lines: string[] = [];

	if (gist?.publisher === "gist") {
		if (gist.url) lines.push(`Gist: ${gist.url}`);
		else lines.push("Public gist created. Could not parse gist URL from gh output.");
	}
	if (huggingface?.publisher === "huggingface") {
		lines.push(`Hugging Face dataset: ${huggingface.treeUrl}`);
	}
	if (gist?.publisher === "gist") {
		lines.push(`Submit at ${submitUrl} and paste the gist URL`);
	} else if (lines.length === 0) {
		lines.push(failures.length > 0 ? "Publish failed." : "Publish completed.");
	}
	if (failures.length > 0) {
		lines.push(`Failed: ${failures.map((failure) => `${failure.publisher}: ${failure.message}`).join("; ")}`);
	}
	return lines.join(" — ");
}

function buildRemoteDir(bundle: PublicationBundle, pathPrefix = "sessions"): string {
	const baseName = path.basename(bundle.sessionFilename, path.extname(bundle.sessionFilename));
	const safeBase = sanitizePathSegment(baseName) || "session";
	const safeTimestamp = bundle.createdAt.replace(/[:.]/g, "-");
	const prefix = pathPrefix.replace(/^\/+|\/+$/g, "") || "sessions";
	return `${prefix}/${safeTimestamp}-${safeBase}`;
}

async function ensureDatasetRepo(
	repo: { type: "dataset"; name: string },
	accessToken: string,
	visibility: "public" | "private" = "public",
): Promise<string> {
	if (await repoExists({ repo, accessToken })) {
		return `https://huggingface.co/datasets/${repo.name}`;
	}
	const created = await createRepo({
		repo,
		accessToken,
		visibility,
	});
	return created.repoUrl;
}

function sanitizePathSegment(value: string): string {
	return value.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/-{2,}/g, "-").replace(/^-|-$/g, "");
}

function encodeRepoPath(value: string): string {
	return value.split("/").map((segment) => encodeURIComponent(segment)).join("/");
}

function resolvePublishedGistUrl(stdout: string, stderr: string): string | undefined {
	const combined = `${stdout}\n${stderr}`;
	return extractGistUrl(combined) ?? extractFirstUrl(combined) ?? firstNonEmptyLine(stdout, stderr);
}

function extractGistUrl(text: string): string | undefined {
	const match = text.match(/https?:\/\/gist\.github\.com\/\S+/);
	return sanitizeExtractedUrl(match?.[0]);
}

function extractFirstUrl(text: string): string | undefined {
	const match = text.match(/https?:\/\/\S+/);
	return sanitizeExtractedUrl(match?.[0]);
}

function sanitizeExtractedUrl(value: string | undefined): string | undefined {
	return value?.replace(/[),.;]+$/, "").trim() || undefined;
}

function firstNonEmptyLine(...chunks: string[]): string | undefined {
	for (const chunk of chunks) {
		for (const line of chunk.split(/\r?\n/)) {
			const trimmed = line.trim();
			if (trimmed) return trimmed;
		}
	}
	return undefined;
}
