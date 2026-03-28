import { describe, expect, test } from "bun:test";

import { DEFAULT_SECRET_PLUGIN_CONFIGS, initializeSecretPlugins, scanSecrets } from "./secret-scanner";

describe("secret scanner", () => {
	test("initializes detect-secrets style built-ins", () => {
		const plugins = initializeSecretPlugins();
		expect(plugins.map((plugin) => plugin.name)).toEqual(DEFAULT_SECRET_PLUGIN_CONFIGS.map((plugin) => plugin.name));
		expect(plugins.map((plugin) => plugin.json())).toEqual(DEFAULT_SECRET_PLUGIN_CONFIGS);
	});

	test("detects provider tokens before generic keyword matches", () => {
		const findings = scanSecrets("GITHUB_TOKEN=ghp_123456789012345678901234567890123456");
		expect(findings).toHaveLength(1);
		expect(findings[0]).toMatchObject({
			secretType: "github_token",
			value: "ghp_123456789012345678901234567890123456",
			placeholder: "[REDACTED_TOKEN]",
		});
	});

	test("detects private key blocks", () => {
		const findings = scanSecrets([
			"-----BEGIN OPENSSH PRIVATE KEY-----",
			"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA",
			"-----END OPENSSH PRIVATE KEY-----",
		].join("\n"));
		expect(findings).toHaveLength(1);
		expect(findings[0]).toMatchObject({
			secretType: "private_key",
			placeholder: "[REDACTED_PRIVATE_KEY]",
		});
		expect(findings[0]?.value).toContain("BEGIN OPENSSH PRIVATE KEY");
	});

	test("keeps safe commit hashes out of entropy matches", () => {
		const findings = scanSecrets("commit 8f14e45fceea167a5a36dedd4bea2543c6f9d1ab");
		expect(findings).toHaveLength(0);
	});
});
