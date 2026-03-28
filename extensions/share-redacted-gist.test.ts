import { describe, expect, test } from "bun:test";

import { buildSubmissionMessage } from "./share-redacted-gist";

describe("buildSubmissionMessage", () => {
	test("includes gist URL in the final user-facing message", () => {
		const url = "https://gist.github.com/lukaskawerau/abcdef123456";
		const message = buildSubmissionMessage(url);
		expect(message).toContain(url);
		expect(message).toContain("https://openagentsessions.org/submit");
		expect(message).toContain("paste that URL");
	});

	test("falls back to a clear recovery message when URL parsing fails", () => {
		const message = buildSubmissionMessage(undefined);
		expect(message).toContain("Could not parse gist URL");
		expect(message).toContain("https://openagentsessions.org/submit");
	});
});
