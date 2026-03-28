import { describe, expect, test } from "bun:test";

import { buildSubmissionMessage } from "./share-redacted-gist";

describe("buildSubmissionMessage", () => {
	test("includes gist URL in the final user-facing message", () => {
		const message = buildSubmissionMessage([
			{ publisher: "gist", url: "https://gist.github.com/lukaskawerau/abcdef123456" },
		]);
		expect(message).toContain("https://gist.github.com/lukaskawerau/abcdef123456");
		expect(message).toContain("https://openagentsessions.org/submit");
		expect(message).toContain("paste the gist URL");
	});

	test("includes hugging face dataset URL when published there", () => {
		const message = buildSubmissionMessage([
			{
				publisher: "huggingface",
				dataset: "lukaskawerau/pi-open-agent-sessions",
				repoUrl: "https://huggingface.co/datasets/lukaskawerau/pi-open-agent-sessions",
				treeUrl: "https://huggingface.co/datasets/lukaskawerau/pi-open-agent-sessions/tree/main/sessions/demo",
				remoteDir: "sessions/demo",
			},
		]);
		expect(message).toContain("Hugging Face dataset");
		expect(message).toContain("https://huggingface.co/datasets/lukaskawerau/pi-open-agent-sessions/tree/main/sessions/demo");
		expect(message).not.toContain("openagentsessions.org/submit");
	});

	test("appends failures without hiding successful publications", () => {
		const message = buildSubmissionMessage(
			[{ publisher: "gist", url: "https://gist.github.com/lukaskawerau/abcdef123456" }],
			[{ publisher: "huggingface", message: "401 Unauthorized" }],
		);
		expect(message).toContain("https://gist.github.com/lukaskawerau/abcdef123456");
		expect(message).toContain("Failed: huggingface: 401 Unauthorized");
	});

	test("reports pure publish failures clearly", () => {
		const message = buildSubmissionMessage([], [{ publisher: "huggingface", message: "401 Unauthorized" }]);
		expect(message).toContain("Publish failed.");
		expect(message).toContain("Failed: huggingface: 401 Unauthorized");
	});
});
