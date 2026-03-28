import { describe, expect, test } from "bun:test";

import { applyManualRedactions, createLiteralRule, createRegexRule } from "./review-apply";
import { buildReviewModel } from "./review-model";

describe("buildReviewModel", () => {
	test("extracts readable blocks and suspicious values from message content plus tool calls", () => {
		const input = [
			JSON.stringify({
				type: "message",
				message: {
					role: "user",
					content: "Please debug my apiKey=abc123SECRET456 and server https://auth.internal/login",
				},
			}),
			JSON.stringify({
				type: "message",
				message: {
					role: "assistant",
					provider: "anthropic",
					model: "claude-sonnet-4-5",
					content: [
						{ type: "text", text: "I'll inspect the config." },
						{
							type: "toolCall",
							id: "call_1",
							name: "read",
							arguments: { path: "/Users/lukas/.config/private.env" },
						},
					],
				},
			}),
			JSON.stringify({
				type: "message",
				message: {
					role: "toolResult",
					toolCallId: "call_1",
					toolName: "read",
					content: [
						{ type: "text", text: "AUTH_TOKEN=Bearer sk_test_secret_1234567890\nHOST=10.0.0.4" },
					],
					isError: false,
				},
			}),
		].join("\n");

		const model = buildReviewModel(input);
		expect(model.blocks.map((block) => block.title)).toEqual(["User", "Assistant", "Tool call · read", "Tool result · read"]);
		expect(model.flaggedBlockCount).toBeGreaterThanOrEqual(3);
		expect(model.uniqueCandidateCount).toBeGreaterThanOrEqual(4);

		const values = model.blocks.flatMap((block) => block.occurrences.map((entry) => entry.value));
		expect(values).toContain("abc123SECRET456");
		expect(values).toContain("https://auth.internal/login");
		expect(values).toContain("/Users/lukas/.config/private.env");
		expect(values).toContain("10.0.0.4");
	});

	test("hides marked-safe signatures", () => {
		const input = "token=abc123SECRET456";
		const initial = buildReviewModel(input);
		const signature = initial.blocks[0]?.occurrences.find((entry) => entry.value === "abc123SECRET456")?.signature;
		expect(signature).toBeDefined();
		const filtered = buildReviewModel(input, new Set([signature!]));
		const values = filtered.blocks.flatMap((block) => block.occurrences.map((entry) => entry.value));
		expect(values).not.toContain("abc123SECRET456");
	});
});

describe("manual redactions", () => {
	test("applies literal rules globally", () => {
		const rule = createLiteralRule("foo.internal");
		if (rule instanceof Error) throw rule;
		const result = applyManualRedactions("foo.internal -> foo.internal", [rule]);
		expect(result.text).toContain("[REDACTED_URL]");
		expect(result.replacements).toBe(2);
	});

	test("parses slash regex rules and replaces all matches", () => {
		const rule = createRegexRule("/Bearer\\s+\\S+/i");
		if (rule instanceof Error) throw rule;
		expect(rule.flags).toContain("g");
		const result = applyManualRedactions("Authorization: Bearer one\nBearer two", [rule]);
		expect(result.replacements).toBe(2);
		expect(result.text).not.toContain("Bearer one");
		expect(result.text).not.toContain("Bearer two");
	});
});
