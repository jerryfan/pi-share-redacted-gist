import type { ExtensionCommandContext } from "@mariozechner/pi-coding-agent";
import { Key, matchesKey, truncateToWidth, visibleWidth, wrapTextWithAnsi } from "@mariozechner/pi-tui";

import {
	applyManualRedactions,
	countRuleMatches,
	createLiteralRule,
	createRegexRule,
	createRuleFromOccurrence,
	type ManualRedactionRule,
} from "./review-apply";
import { buildReviewModel, type ReviewBlock, type ReviewModel, type ReviewOccurrence } from "./review-model";

type ReviewAction =
	| { type: "approve"; selectedBlockId?: string }
	| { type: "cancel" }
	| { type: "redact-current"; selectedBlockId?: string; occurrenceSignature?: string }
	| { type: "mark-safe"; selectedBlockId?: string; occurrenceSignature?: string }
	| { type: "add-literal"; selectedBlockId?: string }
	| { type: "add-regex"; selectedBlockId?: string }
	| { type: "undo"; selectedBlockId?: string }
	| { type: "raw-editor"; selectedBlockId?: string };

type HistoryEntry =
	| { type: "rule"; rule: ManualRedactionRule }
	| { type: "safe"; signature: string };

export async function reviewRedactions(
	ctx: ExtensionCommandContext,
	initialText: string,
): Promise<{ text: string; manualRuleCount: number; remainingCandidates: number } | undefined> {
	let baseText = initialText;
	let rules: ManualRedactionRule[] = [];
	const safeSignatures = new Set<string>();
	const history: HistoryEntry[] = [];
	let selectedBlockId: string | undefined;

	while (true) {
		const applied = applyManualRedactions(baseText, rules);
		const model = buildReviewModel(applied.text, safeSignatures);
		selectedBlockId = syncSelectedBlockId(model, selectedBlockId);
		const action = await showReviewScreen(ctx, model, selectedBlockId, rules.length, history.length);

		if (action.type === "cancel") return undefined;
		if (action.selectedBlockId) selectedBlockId = action.selectedBlockId;

		if (action.type === "approve") {
			if (model.totalOccurrences > 0) {
				const ok = await ctx.ui.confirm(
					"Unreviewed suspicious values remain",
					`${model.uniqueCandidateCount} suspicious value(s) still remain across ${model.flaggedBlockCount} block(s). Publish anyway?`,
				);
				if (!ok) continue;
			}
			return {
				text: applied.text,
				manualRuleCount: rules.length,
				remainingCandidates: model.uniqueCandidateCount,
			};
		}

		if (action.type === "raw-editor") {
			const edited = await ctx.ui.editor("Review full redacted session", applied.text);
			if (edited === undefined) continue;
			baseText = edited;
			rules = [];
			history.length = 0;
			ctx.ui.notify("Switched to manual editor. Rule history reset.", "info");
			continue;
		}

		if (action.type === "undo") {
			const entry = history.pop();
			if (!entry) {
				ctx.ui.notify("Nothing to undo", "info");
				continue;
			}
			if (entry.type === "rule") {
				rules = rules.filter((rule) => rule.id !== entry.rule.id);
				ctx.ui.notify(`Undid ${entry.rule.label}`, "info");
			} else {
				safeSignatures.delete(entry.signature);
				ctx.ui.notify("Restored suspicious item", "info");
			}
			continue;
		}

		if (action.type === "mark-safe") {
			const selectedOccurrence = findOccurrence(model, action.occurrenceSignature) ?? findSelectedOccurrence(model, selectedBlockId);
			if (!selectedOccurrence) {
				ctx.ui.notify("No suspicious item on this block", "warning");
				continue;
			}
			safeSignatures.add(selectedOccurrence.signature);
			history.push({ type: "safe", signature: selectedOccurrence.signature });
			ctx.ui.notify(`Marked safe: ${displayText(selectedOccurrence.value)}`, "info");
			continue;
		}

		if (action.type === "redact-current") {
			const selectedOccurrence = findOccurrence(model, action.occurrenceSignature) ?? findSelectedOccurrence(model, selectedBlockId);
			if (!selectedOccurrence) {
				ctx.ui.notify("No suspicious item on this block", "warning");
				continue;
			}
			const rule = createRuleFromOccurrence(selectedOccurrence);
			const matches = countRuleMatches(applied.text, rule);
			if (matches === 0) {
				ctx.ui.notify(`No matches left for ${displayText(selectedOccurrence.value)}`, "warning");
				continue;
			}
			rules.push(rule);
			history.push({ type: "rule", rule });
			ctx.ui.notify(`Redacted ${matches} match(es): ${displayText(selectedOccurrence.value)}`, "info");
			continue;
		}

		if (action.type === "add-literal") {
			const value = await ctx.ui.input("Redact literal everywhere", "exact text to replace globally");
			if (value === undefined) continue;
			const rule = createLiteralRule(value);
			if (rule instanceof Error) {
				ctx.ui.notify(rule.message, "error");
				continue;
			}
			const matches = countRuleMatches(applied.text, rule);
			if (matches === 0) {
				ctx.ui.notify(`No matches for literal: ${value.trim()}`, "warning");
				continue;
			}
			rules.push(rule);
			history.push({ type: "rule", rule });
			ctx.ui.notify(`Redacted ${matches} match(es): ${value.trim()}`, "info");
			continue;
		}

		if (action.type === "add-regex") {
			const value = await ctx.ui.input("Redact regex everywhere", "e.g. /Bearer\\s+\S+/g or raw-pattern");
			if (value === undefined) continue;
			const rule = createRegexRule(value);
			if (rule instanceof Error) {
				ctx.ui.notify(`Invalid regex: ${rule.message}`, "error");
				continue;
			}
			const matches = countRuleMatches(applied.text, rule);
			if (matches === 0) {
				ctx.ui.notify(`No matches for ${rule.label}`, "warning");
				continue;
			}
			rules.push(rule);
			history.push({ type: "rule", rule });
			ctx.ui.notify(`Redacted ${matches} match(es): ${rule.label}`, "info");
		}
	}
}

async function showReviewScreen(
	ctx: ExtensionCommandContext,
	model: ReviewModel,
	selectedBlockId: string | undefined,
	manualRuleCount: number,
	historyCount: number,
): Promise<ReviewAction> {
	return ctx.ui.custom<ReviewAction>((tui, theme, _kb, done) => {
		let currentBlockId = syncSelectedBlockId(model, selectedBlockId);
		let currentOccurrenceIndex = 0;
		let cachedWidth: number | undefined;
		let cachedLines: string[] | undefined;

		const refresh = () => {
			cachedWidth = undefined;
			cachedLines = undefined;
			tui.requestRender();
		};

		const indexForId = (id: string | undefined) => {
			if (!id) return 0;
			const found = model.blocks.findIndex((block) => block.id === id);
			return found >= 0 ? found : 0;
		};

		const syncOccurrenceIndex = () => {
			const occurrences = currentBlock().occurrences;
			currentOccurrenceIndex = occurrences.length === 0 ? 0 : Math.min(currentOccurrenceIndex, occurrences.length - 1);
		};

		const currentBlock = (): ReviewBlock => model.blocks[indexForId(currentBlockId)] ?? model.blocks[0]!;
		const currentOccurrence = (): ReviewOccurrence | undefined => {
			syncOccurrenceIndex();
			return currentBlock().occurrences[currentOccurrenceIndex];
		};

		return {
			handleInput(data: string) {
				if (matchesKey(data, Key.escape)) {
					done({ type: "cancel" });
					return;
				}
				if (matchesKey(data, Key.enter)) {
					done({ type: "approve", selectedBlockId: currentBlockId });
					return;
				}
				if (matchesKey(data, Key.up) || data === "k") {
					const nextIndex = Math.max(0, indexForId(currentBlockId) - 1);
					currentBlockId = model.blocks[nextIndex]?.id;
					currentOccurrenceIndex = 0;
					refresh();
					return;
				}
				if (matchesKey(data, Key.down) || data === "j") {
					const nextIndex = Math.min(model.blocks.length - 1, indexForId(currentBlockId) + 1);
					currentBlockId = model.blocks[nextIndex]?.id;
					currentOccurrenceIndex = 0;
					refresh();
					return;
				}
				if (matchesKey(data, Key.right) || data === "]") {
					const occurrences = currentBlock().occurrences;
					if (occurrences.length > 0) {
						currentOccurrenceIndex = (currentOccurrenceIndex + 1) % occurrences.length;
						refresh();
					}
					return;
				}
				if (matchesKey(data, Key.left) || data === "[") {
					const occurrences = currentBlock().occurrences;
					if (occurrences.length > 0) {
						currentOccurrenceIndex = (currentOccurrenceIndex - 1 + occurrences.length) % occurrences.length;
						refresh();
					}
					return;
				}
				if (data === "n" || matchesKey(data, Key.tab)) {
					currentBlockId = moveToFlaggedBlock(model, indexForId(currentBlockId), 1) ?? currentBlockId;
					currentOccurrenceIndex = 0;
					refresh();
					return;
				}
				if (data === "p" || matchesKey(data, Key.shift("tab"))) {
					currentBlockId = moveToFlaggedBlock(model, indexForId(currentBlockId), -1) ?? currentBlockId;
					currentOccurrenceIndex = 0;
					refresh();
					return;
				}
				if (data === "r") {
					done({
						type: "redact-current",
						selectedBlockId: currentBlockId,
						occurrenceSignature: currentOccurrence()?.signature,
					});
					return;
				}
				if (data === "s") {
					done({
						type: "mark-safe",
						selectedBlockId: currentBlockId,
						occurrenceSignature: currentOccurrence()?.signature,
					});
					return;
				}
				if (data === "a") {
					done({ type: "add-literal", selectedBlockId: currentBlockId });
					return;
				}
				if (data === "x") {
					done({ type: "add-regex", selectedBlockId: currentBlockId });
					return;
				}
				if (data === "u") {
					done({ type: "undo", selectedBlockId: currentBlockId });
					return;
				}
				if (data === "e") {
					done({ type: "raw-editor", selectedBlockId: currentBlockId });
				}
			},
			render(width: number) {
				if (cachedLines && cachedWidth === width) return cachedLines;
				cachedWidth = width;
				cachedLines = clampLines(
					renderReviewScreen({
						width,
						theme,
						model,
						selectedBlock: currentBlock(),
						selectedOccurrence: currentOccurrence(),
						selectedOccurrenceIndex: currentOccurrenceIndex,
						manualRuleCount,
						historyCount,
					}),
					width,
				);
				return cachedLines;
			},
			invalidate() {
				cachedWidth = undefined;
				cachedLines = undefined;
			},
		};
	});
}

function renderReviewScreen(input: {
	width: number;
	theme: ExtensionCommandContext["ui"]["theme"];
	model: ReviewModel;
	selectedBlock: ReviewBlock;
	selectedOccurrence: ReviewOccurrence | undefined;
	selectedOccurrenceIndex: number;
	manualRuleCount: number;
	historyCount: number;
}): string[] {
	const { width, theme, model, selectedBlock, selectedOccurrence, selectedOccurrenceIndex, manualRuleCount, historyCount } = input;
	const header = [
		theme.fg("accent", "─".repeat(width)),
		truncateToWidth(
			theme.fg("accent", theme.bold("Redaction review")) +
				`  ${theme.fg("muted", `${model.uniqueCandidateCount} suspicious value(s)`)}  ${theme.fg("muted", `${model.flaggedBlockCount} flagged block(s)`)}  ${theme.fg("muted", `${manualRuleCount} manual rule(s)`)}  ${theme.fg("dim", `${historyCount} undo step(s)`)} `,
			width,
		),
	];

	if (width < 96) {
		return [
			...header,
			...renderNarrow(theme, width, model, selectedBlock, selectedOccurrence, selectedOccurrenceIndex),
			theme.fg("accent", "─".repeat(width)),
		];
	}

	const leftWidth = Math.max(30, Math.min(42, Math.floor(width * 0.34)));
	const rightWidth = Math.max(30, width - leftWidth - 3);
	const left = renderBlockList(theme, leftWidth, model, selectedBlock.id, 10);
	const right = renderDetails(theme, rightWidth, selectedBlock, selectedOccurrence, selectedOccurrenceIndex);
	const body = stitchColumns(left, right, leftWidth, rightWidth, theme.fg("borderMuted", " │ "));
	return [...header, ...body, theme.fg("dim", helpText(true, width)), theme.fg("accent", "─".repeat(width))];
}

function renderNarrow(
	theme: ExtensionCommandContext["ui"]["theme"],
	width: number,
	model: ReviewModel,
	selectedBlock: ReviewBlock,
	selectedOccurrence: ReviewOccurrence | undefined,
	selectedOccurrenceIndex: number,
): string[] {
	return [
		...renderBlockList(theme, width, model, selectedBlock.id, 6),
		"",
		...renderDetails(theme, width, selectedBlock, selectedOccurrence, selectedOccurrenceIndex),
		theme.fg("dim", helpText(false, width)),
	];
}

function renderBlockList(
	theme: ExtensionCommandContext["ui"]["theme"],
	width: number,
	model: ReviewModel,
	selectedBlockId: string,
	maxVisibleBlocks: number,
): string[] {
	const lines = [theme.fg("accent", theme.bold("Transcript blocks"))];
	const selectedIndex = Math.max(0, model.blocks.findIndex((block) => block.id === selectedBlockId));
	const visibleCount = Math.max(1, Math.min(maxVisibleBlocks, model.blocks.length));
	const start = Math.max(0, Math.min(selectedIndex - Math.floor(visibleCount / 2), model.blocks.length - visibleCount));
	const end = Math.min(model.blocks.length, start + visibleCount);
	lines.push(truncateToWidth(theme.fg("muted", `${selectedIndex + 1}/${model.blocks.length} selected • ${start + 1}-${end} shown`), width));
	lines.push("");
	if (start > 0) {
		lines.push(truncateToWidth(theme.fg("dim", `   ↑ ${start} earlier block(s)`), width));
	}
	for (const block of model.blocks.slice(start, end)) {
		const selected = block.id === selectedBlockId;
		const prefix = selected ? theme.fg("accent", "> ") : "  ";
		const count = block.occurrences.length > 0 ? theme.fg("warning", `!${block.occurrences.length}`) : theme.fg("dim", " ·");
		const title = `${block.index + 1}. ${block.title}`;
		const titleLine = `${prefix}${selected ? theme.fg("accent", title) : title} ${count}`;
		lines.push(truncateToWidth(titleLine, width));
		const subtitle = block.subtitle ? `${block.subtitle} · ${block.summary}` : block.summary;
		lines.push(truncateToWidth(`   ${theme.fg("muted", subtitle)}`, width));
	}
	if (end < model.blocks.length) {
		lines.push(truncateToWidth(theme.fg("dim", `   ↓ ${model.blocks.length - end} later block(s)`), width));
	}
	return lines;
}

function renderDetails(
	theme: ExtensionCommandContext["ui"]["theme"],
	width: number,
	block: ReviewBlock,
	occurrence: ReviewOccurrence | undefined,
	occurrenceIndex: number,
): string[] {
	const lines: string[] = [];
	const heading = block.subtitle ? `${block.title} · ${block.subtitle}` : block.title;
	lines.push(theme.fg("accent", theme.bold(heading)));
	lines.push(truncateToWidth(theme.fg("muted", `${block.occurrences.length} suspicious item(s) on this block`), width));
	lines.push("");

	for (const excerptLine of renderExcerpt(theme, width, block, occurrence)) lines.push(excerptLine);
	lines.push("");

	if (occurrence) {
		lines.push(theme.fg("accent", theme.bold("Current suspicious value")));
		lines.push(truncateToWidth(`${theme.fg("muted", "Item: ")}${occurrenceIndex + 1}/${block.occurrences.length}`, width));
		lines.push(truncateToWidth(`${theme.fg("muted", "Kind: ")}${occurrence.label}`, width));
		lines.push(truncateToWidth(`${theme.fg("muted", "Why: ")}${occurrence.reason}`, width));
		lines.push(truncateToWidth(`${theme.fg("muted", "Matches: ")}${occurrence.sessionCount} across session`, width));
		lines.push(truncateToWidth(`${theme.fg("muted", "Replace with: ")}${occurrence.suggestedPlaceholder}`, width));
		lines.push(truncateToWidth(`${theme.fg("muted", "Value: ")}${theme.fg("warning", displayText(occurrence.value))}`, width));
	} else {
		lines.push(theme.fg("success", "No suspicious values on this block."));
		lines.push(theme.fg("muted", "Browse the transcript, add a manual literal/regex, or open the raw editor."));
	}

	return lines;
}

function renderExcerpt(
	theme: ExtensionCommandContext["ui"]["theme"],
	width: number,
	block: ReviewBlock,
	occurrence: ReviewOccurrence | undefined,
): string[] {
	const lines: string[] = [theme.fg("accent", theme.bold("Excerpt"))];
	const start = occurrence ? Math.max(0, occurrence.lineIndex - 3) : 0;
	const end = Math.min(block.displayLines.length, start + 10);
	for (let i = start; i < end; i++) {
		const lineNo = `${String(i + 1).padStart(2, " ")} `;
		const prefix = i === occurrence?.lineIndex ? theme.fg("accent", `${lineNo}› `) : theme.fg("dim", `${lineNo}  `);
		const line = block.displayLines[i] ?? "";
		const highlighted = occurrence && i === occurrence.lineIndex ? highlightValue(theme, line, displayText(occurrence.value)) : line;
		const wrapped = wrapTextWithAnsi(highlighted, Math.max(12, width - visibleWidth(prefix)));
		wrapped.forEach((part, partIndex) => {
			const linePrefix = partIndex === 0 ? prefix : " ".repeat(visibleWidth(prefix));
			lines.push(truncateToWidth(`${linePrefix}${part}`, width));
		});
	}
	return lines;
}

function highlightValue(theme: ExtensionCommandContext["ui"]["theme"], line: string, value: string): string {
	if (!value) return line;
	return line.split(value).join(theme.bg("selectedBg", theme.fg("warning", value)));
}

function stitchColumns(left: string[], right: string[], leftWidth: number, rightWidth: number, separator: string): string[] {
	const lines: string[] = [];
	const total = Math.max(left.length, right.length);
	for (let i = 0; i < total; i++) {
		const leftLine = padVisible(left[i] ?? "", leftWidth);
		const rightLine = padVisible(right[i] ?? "", rightWidth);
		lines.push(`${leftLine}${separator}${rightLine}`);
	}
	return lines;
}

function padVisible(value: string, width: number): string {
	const diff = width - visibleWidth(value);
	return value + " ".repeat(Math.max(0, diff));
}

function moveToFlaggedBlock(model: ReviewModel, currentIndex: number, direction: 1 | -1): string | undefined {
	for (let step = 1; step <= model.blocks.length; step++) {
		const index = currentIndex + step * direction;
		if (index < 0 || index >= model.blocks.length) break;
		if (model.blocks[index]!.occurrences.length > 0) return model.blocks[index]!.id;
	}
	return undefined;
}

function findSelectedOccurrence(model: ReviewModel, selectedBlockId: string | undefined): ReviewOccurrence | undefined {
	return model.blocks.find((block) => block.id === selectedBlockId)?.occurrences[0];
}

function findOccurrence(model: ReviewModel, signature: string | undefined): ReviewOccurrence | undefined {
	if (!signature) return undefined;
	for (const block of model.blocks) {
		const found = block.occurrences.find((entry) => entry.signature === signature);
		if (found) return found;
	}
	return undefined;
}

function syncSelectedBlockId(model: ReviewModel, selectedBlockId: string | undefined): string | undefined {
	if (model.blocks.length === 0) return undefined;
	if (selectedBlockId && model.blocks.some((block) => block.id === selectedBlockId)) return selectedBlockId;
	return model.blocks.find((block) => block.occurrences.length > 0)?.id ?? model.blocks[0]!.id;
}

function clampLines(lines: string[], width: number): string[] {
	return lines.map((line) => truncateToWidth(line, width));
}

function displayText(value: string): string {
	return value
		.replace(/\u001B\][^\u0007\u001B]*(?:\u0007|\u001B\\)/g, "")
		.replace(/\u001B\[[0-?]*[ -/]*[@-~]/g, "")
		.replace(/\u001B[@-_]/g, "")
		.replace(/\t/g, "  ")
		.replace(/\r/g, "")
		.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
		.trim() || "(empty)";
}

function helpText(_wide: boolean, width: number): string {
	const text = "↑↓/j k block • ←→/[ ] item • n/p next flagged • r redact • s safe • a literal • x regex • u undo • e raw editor • enter publish • esc cancel";
	return truncateToWidth(text, width);
}
