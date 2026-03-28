import { describe, expect, test } from "bun:test";

import { redactSensitive } from "./redaction";

const options = {
	cwd: "/Users/lukas/coding/apps/pi-extensions/pi-share-redacted-gist",
	homeDir: "/Users/lukas",
	usernameCandidates: ["lukas"],
};

function statMap(stats: Array<{ label: string; count: number }>): Record<string, number> {
	return Object.fromEntries(stats.map((entry) => [entry.label, entry.count]));
}

describe("redactSensitive", () => {
	test("redacts structured JSONL string values", () => {
		const input = [
			JSON.stringify({
				type: "message",
				message: {
					role: "user",
					content: "email alice@example.com cwd /Users/lukas/coding/apps/pi-extensions/pi-share-redacted-gist secret ghp_123456789012345678901234567890123456",
				},
			}),
		].join("\n");

		const result = redactSensitive(input, options);
		const line = JSON.parse(result.text);
		expect(line.message.content).toContain("[REDACTED_EMAIL]");
		expect(line.message.content).toContain("[REDACTED_CWD]");
		expect(line.message.content).toContain("[REDACTED_TOKEN]");
		expect(statMap(result.stats)).toMatchObject({
			email: 1,
			cwd: 1,
			github_token: 1,
		});
	});

	test("redacts sufficiently random base64ish tokens", () => {
		const input = "session token a8ZkP1_qL9sW3YtN6VxB0mH2cR7uJ4fD5nT1pQ8r";
		const result = redactSensitive(input, options);
		expect(result.text).toContain("[REDACTED_OPAQUE_BASE64]");
		expect(statMap(result.stats)).toMatchObject({ opaque_base64: 1 });
	});

	test("redacts sufficiently random hex tokens", () => {
		const input = "secret 8f14e45fceea167a5a36dedd4bea2543c6f9d1ab";
		const result = redactSensitive(input, options);
		expect(result.text).toContain("[REDACTED_OPAQUE_HEX]");
		expect(statMap(result.stats)).toMatchObject({ opaque_hex: 1 });
	});

	test("keeps commit hashes in safe git context", () => {
		const input = "commit 8f14e45fceea167a5a36dedd4bea2543c6f9d1ab";
		const result = redactSensitive(input, options);
		expect(result.text).toContain("8f14e45fceea167a5a36dedd4bea2543c6f9d1ab");
		expect(statMap(result.stats).opaque_hex).toBeUndefined();
	});

	test("keeps model-like slugs", () => {
		const input = "using claude-3-7-sonnet-20250219 today";
		const result = redactSensitive(input, options);
		expect(result.text).toContain("claude-3-7-sonnet-20250219");
		expect(result.text).not.toContain("REDACTED_OPAQUE");
	});

	test("redacts uuids with a dedicated placeholder", () => {
		const input = "id 550e8400-e29b-41d4-a716-446655440000";
		const result = redactSensitive(input, options);
		expect(result.text).toContain("[REDACTED_UUID]");
		expect(statMap(result.stats)).toMatchObject({ uuid: 1 });
	});

	test("falls back to raw text redaction for non-JSON lines", () => {
		const input = "plain token QWxhZGRpbjpPcGVuU2VzYW1lX0FiQzEyM18tVG9rZW4";
		const result = redactSensitive(input, options);
		expect(result.text).toContain("[REDACTED_OPAQUE_BASE64]");
	});

	test("redacts private key blocks inside structured strings", () => {
		const input = [
			JSON.stringify({
				type: "message",
				message: {
					role: "toolResult",
					content: [
						{
							type: "text",
							text: [
								"-----BEGIN OPENSSH PRIVATE KEY-----",
								"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA",
								"-----END OPENSSH PRIVATE KEY-----",
							].join("\n"),
						},
					],
				},
			}),
		].join("\n");

		const result = redactSensitive(input, options);
		const line = JSON.parse(result.text);
		const text = line.message.content[0].text;
		expect(text).toBe("[REDACTED_PRIVATE_KEY]");
		expect(statMap(result.stats)).toMatchObject({ private_key: 1 });
	});
});
