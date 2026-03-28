import { afterEach, describe, expect, test } from "bun:test";

import { resolveConfiguredSecretValue } from "./huggingface-auth";

describe("resolveConfiguredSecretValue", () => {
	afterEach(() => {
		delete process.env.TEST_HF_TOKEN;
	});

	test("returns literal token values unchanged", async () => {
		const resolved = await resolveConfiguredSecretValue("hf_abcdefghijklmnopqrstuvwxyz1234567890");
		expect(resolved).toMatchObject({
			value: "hf_abcdefghijklmnopqrstuvwxyz1234567890",
			source: "literal",
		});
	});

	test("resolves environment variable references", async () => {
		process.env.TEST_HF_TOKEN = "hf_env_token_value";
		const resolved = await resolveConfiguredSecretValue("TEST_HF_TOKEN");
		expect(resolved).toMatchObject({
			value: "hf_env_token_value",
			source: "env:TEST_HF_TOKEN",
		});
	});

	test("resolves shell command references", async () => {
		const resolved = await resolveConfiguredSecretValue("!printf 'hf_shell_token'");
		expect(resolved).toMatchObject({
			value: "hf_shell_token",
			source: "shell:printf 'hf_shell_token'",
		});
	});
});
