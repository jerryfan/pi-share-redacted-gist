import { describe, expect, test } from "bun:test";

import { redactSensitiveFileToolPayloads } from "./sensitive-file-redaction";

function statMap(stats: Array<{ label: string; count: number }>): Record<string, number> {
	return Object.fromEntries(stats.map((entry) => [entry.label, entry.count]));
}

describe("redactSensitiveFileToolPayloads", () => {
	test("redacts read results for sensitive file paths while preserving the tool call path", () => {
		const input = [
			JSON.stringify({
				type: "message",
				message: {
					role: "assistant",
					content: [
						{
							type: "toolCall",
							id: "call_read_env",
							name: "read",
							arguments: { path: "/Users/lukas/.env.local" },
						},
					],
				},
			}),
			JSON.stringify({
				type: "message",
				message: {
					role: "toolResult",
					toolCallId: "call_read_env",
					toolName: "read",
					content: [{ type: "text", text: "SECRET_KEY=super-secret\nAPI_URL=https://auth.internal" }],
					details: { numLines: 2, file: { content: "SECRET_KEY=super-secret" } },
				},
			}),
		].join("\n");

		const result = redactSensitiveFileToolPayloads(input);
		const lines = result.text.split("\n").map((line) => JSON.parse(line));
		expect(lines[0].message.content[0].arguments.path).toBe("/Users/lukas/.env.local");
		expect(lines[1].message.content[0].text).toBe("[REDACTED_SENSITIVE_FILE_CONTENT]");
		expect(lines[1].message.details.file.content).toBe("[REDACTED_SENSITIVE_FILE_CONTENT]");
		expect(lines[1].message.details.numLines).toBe(2);
		expect(statMap(result.stats)).toMatchObject({
			sensitive_file_tool_call: 1,
			sensitive_file_tool_result: 1,
		});
	});

	test("redacts write payloads for sensitive files", () => {
		const input = JSON.stringify({
			type: "message",
			message: {
				role: "assistant",
				content: [
					{
						type: "toolCall",
						id: "call_write_npmrc",
						name: "write",
						arguments: {
							path: "/Users/lukas/.npmrc",
							content: "//registry.npmjs.org/:_authToken=npm_secret_123",
						},
					},
				],
			},
		});

		const result = redactSensitiveFileToolPayloads(input);
		const line = JSON.parse(result.text);
		expect(line.message.content[0].arguments.content).toBe("[REDACTED_SENSITIVE_FILE_CONTENT]");
		expect(statMap(result.stats)).toMatchObject({ sensitive_file_tool_call: 1 });
	});

	test("redacts edit payloads and follow-up results for sensitive files", () => {
		const input = [
			JSON.stringify({
				type: "message",
				message: {
					role: "assistant",
					content: [
						{
							type: "toolCall",
							id: "call_edit_env",
							name: "edit",
							arguments: {
								path: "C:\\Users\\lukas\\.aws\\credentials",
								edits: [
									{
										oldText: "aws_access_key_id=AKIA...",
										newText: "aws_access_key_id=AKIA_NEW...",
									},
								],
							},
						},
					],
				},
			}),
			JSON.stringify({
				type: "message",
				message: {
					role: "toolResult",
					toolCallId: "call_edit_env",
					toolName: "edit",
					content: [{ type: "text", text: "Updated aws_access_key_id=AKIA_NEW..." }],
				},
			}),
		].join("\n");

		const result = redactSensitiveFileToolPayloads(input);
		const lines = result.text.split("\n").map((line) => JSON.parse(line));
		expect(lines[0].message.content[0].arguments.edits[0].oldText).toBe("[REDACTED_SENSITIVE_FILE_CONTENT]");
		expect(lines[0].message.content[0].arguments.edits[0].newText).toBe("[REDACTED_SENSITIVE_FILE_CONTENT]");
		expect(lines[1].message.content[0].text).toBe("[REDACTED_SENSITIVE_FILE_CONTENT]");
	});

	test("redacts bash tool results when the command reads a sensitive file", () => {
		const input = [
			JSON.stringify({
				type: "message",
				message: {
					role: "assistant",
					content: [
						{
							type: "toolCall",
							id: "call_bash_env",
							name: "bash",
							arguments: { command: "cat ~/.env.local | sed -n '1,5p'" },
						},
					],
				},
			}),
			JSON.stringify({
				type: "message",
				message: {
					role: "toolResult",
					toolCallId: "call_bash_env",
					toolName: "bash",
					content: [{ type: "text", text: "SECRET_KEY=super-secret" }],
					details: { command: "cat ~/.env.local | sed -n '1,5p'", exitCode: 0 },
				},
			}),
		].join("\n");

		const result = redactSensitiveFileToolPayloads(input);
		const lines = result.text.split("\n").map((line) => JSON.parse(line));
		expect(lines[0].message.content[0].arguments.command).toBe("cat ~/.env.local | sed -n '1,5p'");
		expect(lines[1].message.content[0].text).toBe("[REDACTED_SENSITIVE_FILE_CONTENT]");
		expect(lines[1].message.details.command).toBe("[REDACTED_SENSITIVE_FILE_CONTENT]");
		expect(lines[1].message.details.exitCode).toBe(0);
		expect(statMap(result.stats)).toMatchObject({
			sensitive_file_bash_command: 1,
			sensitive_file_tool_result: 1,
		});
	});

	test("redacts direct bashExecution output for sensitive file reads", () => {
		const input = JSON.stringify({
			type: "message",
			message: {
				role: "bashExecution",
				command: "head -n 5 ~/.ssh/id_ed25519",
				output: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----",
			},
		});

		const result = redactSensitiveFileToolPayloads(input);
		const line = JSON.parse(result.text);
		expect(line.message.command).toBe("head -n 5 ~/.ssh/id_ed25519");
		expect(line.message.output).toBe("[REDACTED_SENSITIVE_FILE_CONTENT]");
		expect(statMap(result.stats)).toMatchObject({ sensitive_file_bash_output: 1 });
	});

	test("keeps non-sensitive file tool calls untouched", () => {
		const input = [
			JSON.stringify({
				type: "message",
				message: {
					role: "assistant",
					content: [
						{
							type: "toolCall",
							id: "call_read_package",
							name: "read",
							arguments: { path: "/Users/lukas/project/package.json" },
						},
					],
				},
			}),
			JSON.stringify({
				type: "message",
				message: {
					role: "toolResult",
					toolCallId: "call_read_package",
					toolName: "read",
					content: [{ type: "text", text: '{"name":"demo"}' }],
				},
			}),
		].join("\n");

		const result = redactSensitiveFileToolPayloads(input);
		expect(result.text).toBe(input);
		expect(result.stats).toHaveLength(0);
	});

	test("keeps harmless bash commands touching sensitive files untouched", () => {
		const input = JSON.stringify({
			type: "message",
			message: {
				role: "bashExecution",
				command: "ls -l ~/.ssh/id_ed25519",
				output: "-rw------- 1 lukas staff 411 Mar 28 12:00 /Users/lukas/.ssh/id_ed25519",
			},
		});

		const result = redactSensitiveFileToolPayloads(input);
		expect(result.text).toBe(input);
	});

	test("supports extra path patterns from config", () => {
		const input = [
			JSON.stringify({
				type: "message",
				message: {
					role: "assistant",
					content: [
						{
							type: "toolCall",
							id: "call_read_custom",
							name: "read",
							arguments: { path: "/Users/lukas/project/config/private.settings" },
						},
					],
				},
			}),
			JSON.stringify({
				type: "message",
				message: {
					role: "toolResult",
					toolCallId: "call_read_custom",
					toolName: "read",
					content: [{ type: "text", text: "VERY_SECRET=true" }],
				},
			}),
		].join("\n");

		const result = redactSensitiveFileToolPayloads(input, {
			extraPatterns: ["config/private.settings"],
		});
		const lines = result.text.split("\n").map((line) => JSON.parse(line));
		expect(lines[1].message.content[0].text).toBe("[REDACTED_SENSITIVE_FILE_CONTENT]");
	});
});
