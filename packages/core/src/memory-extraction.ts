/**
 * CADENCE Memory Extraction Engine
 *
 * Runs after each agent session ends. Extracts the 3-7 most salient facts,
 * decisions, and preferences from the conversation transcript and writes them
 * as candidate MemoryItems to the agent's vault.
 *
 * Architecture:
 *   1. scoreSalience()       — implements S = (α·Novelty + β·Engagement + γ·EntityWeight) × e^(-λt)
 *   2. classifyMemoryType()  — maps a text segment to the extraction taxonomy
 *   3. runMemoryExtraction() — full pipeline: transcript → Claude API → scored candidates → vault writes
 *
 * Extraction taxonomy (pre-vault):
 *   profile      → vault type "summary"
 *   episodic     → vault type "task-context"
 *   skill        → vault type "learning"
 *   preference   → vault type "note"
 *   relationship → vault type "project-history"
 *   custom       → vault type "note"
 *
 * Runs in Electron main process — Node.js only, no browser APIs.
 * Uses claude-haiku-4-5 for cost-efficient extraction.
 */

import { createHash, randomBytes } from "node:crypto";
import Anthropic from "@anthropic-ai/sdk";
import type { MemoryEntry, MemoryEntryType, AgentMemoryVault } from "@01ai/types";

// ─── Public Types ─────────────────────────────────────────────────────────────

/** The extraction-side memory taxonomy (distinct from the vault's MemoryEntryType). */
export type ExtractionMemoryType =
  | "profile"
  | "episodic"
  | "skill"
  | "preference"
  | "relationship"
  | "custom";

/** A single turn in a session transcript. */
export interface TranscriptMessage {
  role: "user" | "assistant";
  content: string;
}

/**
 * A candidate memory item produced by the extraction pipeline.
 * Has not yet been written to the vault — caller decides whether to commit it.
 */
export interface CandidateMemoryItem {
  uuid: string;
  type: ExtractionMemoryType;
  summary: string;
  confidenceScore: number;       // 0.0–1.0, from Claude's extraction
  salienceScore: number;         // 0.0–1.0, from scoreSalience()
  proposedAt: string;            // ISO timestamp
  sourceSessionId: string;
  dependencyRefs: string[];      // UUIDs of other CandidateMemoryItems this depends on
  expiresAt?: string;            // ISO timestamp, optional — episodic items may expire
}

/** Inputs to the salience scoring function. */
export interface SalienceInput {
  /** The text segment being evaluated. */
  segment: string;
  /**
   * Position of this segment in the transcript, as a fraction 0.0–1.0.
   * 0.0 = earliest in session, 1.0 = most recent.
   * Used to compute DecayFactor: recent segments decay less.
   */
  segmentPositionFraction: number;
  /** Existing vault entries, used to compute Novelty via Jaccard similarity. */
  existingVaultSummaries: string[];
}

/** Tunable coefficients for the salience formula. */
export interface SalienceWeights {
  /** α — weight for Novelty (0.0–1.0, default 0.4) */
  alpha: number;
  /** β — weight for Engagement (0.0–1.0, default 0.35) */
  beta: number;
  /** γ — weight for EntityWeight (0.0–1.0, default 0.25) */
  gamma: number;
  /** λ — decay rate for DecayFactor (default 0.5) */
  lambda: number;
}

export const DEFAULT_SALIENCE_WEIGHTS: SalienceWeights = {
  alpha: 0.4,
  beta: 0.35,
  gamma: 0.25,
  lambda: 0.5
};

/** Config for the full extraction pipeline. */
export interface ExtractionConfig {
  /** Anthropic API key. */
  apiKey: string;
  /** Session ID to stamp on all candidate items. */
  sessionId: string;
  /** Vault contents for the agent, used for Novelty deduplication. */
  vault: AgentMemoryVault;
  /** Minimum salience score to include in output (default 0.35). */
  salienceThreshold?: number;
  /** Maximum items to return (default 7, minimum 3). Clamped to [3, 7]. */
  maxItems?: number;
  /** Override salience weights (uses defaults if omitted). */
  weights?: Partial<SalienceWeights>;
}

// ─── Internal: Text utilities ─────────────────────────────────────────────────

/** Tokenise a string into a word-level set (lowercased, punctuation stripped). */
function wordSet(text: string): Set<string> {
  const words = text
    .toLowerCase()
    .replace(/[^\w\s]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 1);
  return new Set(words);
}

/**
 * Jaccard similarity between two word sets: |A ∩ B| / |A ∪ B|.
 * Returns 0.0 if both sets are empty.
 */
function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 0;
  let intersectionSize = 0;
  for (const w of a) {
    if (b.has(w)) intersectionSize++;
  }
  const unionSize = a.size + b.size - intersectionSize;
  return unionSize === 0 ? 0 : intersectionSize / unionSize;
}

/**
 * Novelty score for a segment against the existing vault.
 * 1.0 = completely new content, 0.0 = exact duplicate.
 *
 * Algorithm: compute Jaccard similarity against every existing vault summary,
 * take the maximum (most similar entry), then invert: Novelty = 1 - maxSimilarity.
 */
function computeNovelty(segmentWords: Set<string>, existingVaultSummaries: string[]): number {
  if (existingVaultSummaries.length === 0) return 1.0;
  let maxSimilarity = 0;
  for (const existing of existingVaultSummaries) {
    const existingWords = wordSet(existing);
    const sim = jaccardSimilarity(segmentWords, existingWords);
    if (sim > maxSimilarity) maxSimilarity = sim;
  }
  return 1.0 - maxSimilarity;
}

/**
 * Engagement score for a segment.
 *
 * Heuristics (each contributes additively, capped at 1.0):
 *   - Length signal:    log(wordCount + 1) / log(150) — longer = more engaged, plateau at 150 words
 *   - Question signal:  +0.15 if segment contains a "?" (user asked something)
 *   - Decision signal:  +0.20 if segment contains decision/preference keywords
 *   - Correction signal:+0.10 if segment contains correction/update keywords (high signal)
 */
const DECISION_KEYWORDS = new Set([
  "decided", "decision", "prefer", "preference", "always", "never", "want",
  "need", "require", "important", "must", "should", "agree", "disagree",
  "confirmed", "approved", "rejected", "chosen", "selected"
]);
const CORRECTION_KEYWORDS = new Set([
  "actually", "correction", "mistake", "wrong", "fix", "update", "changed",
  "instead", "not what", "clarify", "clarification"
]);

function computeEngagement(text: string, words: Set<string>): number {
  const wordCount = words.size;
  const lengthScore = Math.min(Math.log(wordCount + 1) / Math.log(150), 1.0);
  const questionBonus = text.includes("?") ? 0.15 : 0;
  let decisionBonus = 0;
  let correctionBonus = 0;
  for (const w of words) {
    if (DECISION_KEYWORDS.has(w)) decisionBonus = 0.20;
    if (CORRECTION_KEYWORDS.has(w)) correctionBonus = 0.10;
  }
  return Math.min(lengthScore + questionBonus + decisionBonus + correctionBonus, 1.0);
}

/**
 * EntityWeight score for a segment.
 *
 * Heuristics (each increments weight, capped at 1.0):
 *   - Proper noun density: count tokens starting with uppercase (not first word of sentence)
 *   - Number density:      count numeric tokens (version numbers, dates, quantities)
 *   - Technical marker:    presence of code fences, URLs, file paths, or camelCase tokens
 *
 * Rationale: segments with proper nouns, numbers, and technical references are
 * more likely to contain durable, specific facts worth remembering.
 */
function computeEntityWeight(text: string): number {
  // Split on whitespace preserving punctuation for analysis
  const tokens = text.split(/\s+/);
  const totalTokens = tokens.length;
  if (totalTokens === 0) return 0;

  // Proper nouns: uppercase start, not sentence-initial (skip index 0 after "." boundary)
  let properNounCount = 0;
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i].replace(/[^a-zA-Z]/g, "");
    if (t.length > 1 && t[0] === t[0].toUpperCase() && t[0] !== t[0].toLowerCase()) {
      properNounCount++;
    }
  }
  const properNounDensity = Math.min(properNounCount / totalTokens, 1.0);

  // Number density
  const numberCount = tokens.filter((t) => /\d/.test(t)).length;
  const numberDensity = Math.min(numberCount / totalTokens, 1.0);

  // Technical marker (boolean — presence of any)
  const hasTechnical =
    text.includes("```") ||
    /https?:\/\//.test(text) ||
    /[./\\][a-zA-Z]/.test(text) || // file paths
    /[a-z][A-Z]/.test(text);       // camelCase

  const technicalScore = hasTechnical ? 0.3 : 0;

  return Math.min(properNounDensity * 0.4 + numberDensity * 0.3 + technicalScore, 1.0);
}

// ─── 1. Salience Scoring ──────────────────────────────────────────────────────

/**
 * Compute the salience score S for a text segment.
 *
 * Formula (from the CADENCE provisional patent):
 *   S = (α × Novelty + β × Engagement + γ × EntityWeight) × DecayFactor
 *   DecayFactor = e^(-λ × t)
 *
 * Time `t` is derived from `segmentPositionFraction`:
 *   t = (1 - segmentPositionFraction)
 * so that t=0 for the most recent segment (no decay) and t=1 for the oldest.
 *
 * Result is clamped to [0.0, 1.0].
 */
export function scoreSalience(
  input: SalienceInput,
  weights: SalienceWeights = DEFAULT_SALIENCE_WEIGHTS
): number {
  const { segment, segmentPositionFraction, existingVaultSummaries } = input;
  const { alpha, beta, gamma, lambda } = weights;

  const words = wordSet(segment);

  const novelty = computeNovelty(words, existingVaultSummaries);
  const engagement = computeEngagement(segment, words);
  const entityWeight = computeEntityWeight(segment);

  // t = age of segment; 0 = newest, 1 = oldest
  const t = 1.0 - Math.max(0, Math.min(1, segmentPositionFraction));
  const decayFactor = Math.exp(-lambda * t);

  const rawScore = (alpha * novelty + beta * engagement + gamma * entityWeight) * decayFactor;
  return Math.max(0, Math.min(1, rawScore));
}

// ─── 2. Memory Type Classifier ────────────────────────────────────────────────

/**
 * Classify a text segment into the extraction memory taxonomy.
 *
 * This is a fast, heuristic pre-classifier. The Claude extraction call also
 * performs classification; this function is used to validate/override
 * low-confidence Claude responses and as a fallback when Claude returns
 * an unrecognised type string.
 *
 * Classification rules (evaluated in priority order):
 *   relationship — mentions another named entity + interaction verb
 *   profile      — identity/background language ("I am", "my name", "I work")
 *   preference   — explicit preference language ("I prefer", "I like", "I hate", "always use")
 *   skill        — procedural/how-to language ("how to", "syntax for", "way to", keywords)
 *   episodic     — past-tense event language or time markers
 *   custom       — fallback
 */
export function classifyMemoryType(segment: string): ExtractionMemoryType {
  const lower = segment.toLowerCase();

  // relationship
  if (
    /\b(told|asked|mentioned|said|reminded|introduced|met|talked to|spoke with|worked with)\b/.test(lower) &&
    /\b[A-Z][a-z]+\b/.test(segment)
  ) {
    return "relationship";
  }

  // profile
  if (
    /\b(i am|i'm|my name is|i work(?: at| for| in)?|i'm a|i study|i live|i'm based|my role|my job)\b/.test(lower)
  ) {
    return "profile";
  }

  // preference
  if (
    /\b(i prefer|i like|i love|i hate|i dislike|i always|i never|i want|i need|my preference|please (always|never)|don't (use|include|add)|use only|avoid)\b/.test(lower)
  ) {
    return "preference";
  }

  // skill
  if (
    /\b(how to|the way to|syntax for|pattern for|approach (to|for)|method (for|to)|technique|best practice|you can use|steps to|guide (for|to)|learned (that|how))\b/.test(lower)
  ) {
    return "skill";
  }

  // episodic
  if (
    /\b(yesterday|last (week|month|time|session)|earlier today|just (finished|completed|did|ran)|we (decided|agreed|discussed|concluded)|turned out|ended up)\b/.test(lower)
  ) {
    return "episodic";
  }

  return "custom";
}

/**
 * Map the extraction taxonomy type to the vault's MemoryEntryType.
 * Used when writing CandidateMemoryItems into the AgentMemoryVault.
 */
export function toVaultType(extractionType: ExtractionMemoryType): MemoryEntryType {
  const map: Record<ExtractionMemoryType, MemoryEntryType> = {
    profile: "summary",
    episodic: "task-context",
    skill: "learning",
    preference: "note",
    relationship: "project-history",
    custom: "note"
  };
  return map[extractionType];
}

// ─── Extraction Prompt Template ───────────────────────────────────────────────

/**
 * Build the system prompt for the Claude haiku extraction call.
 * This is a pure function — no side effects — so it can be tested in isolation.
 *
 * Instructions to Claude:
 *   - Extract 3–7 memory items maximum
 *   - Each item must be a durable fact, decision, preference, or skill
 *   - Do NOT include ephemeral task outputs (e.g., "user asked me to write an email")
 *   - Respond ONLY with valid JSON (array of objects)
 *   - Each object must have: type, summary, confidenceScore, dependencyRefs, expiresAt?
 */
export function buildExtractionSystemPrompt(): string {
  return `You are a memory extraction specialist for an AI agent. Your job is to analyze a conversation transcript and extract the most important, durable facts worth storing in long-term memory.

Extract between 3 and 7 memory items. Prefer fewer, higher-quality items over many weak ones.

WHAT TO EXTRACT — durable information that will still be relevant in future sessions:
- Facts about the user (name, role, location, background)
- Explicit preferences ("always use TypeScript strict mode", "I prefer dark themes")
- Skills or techniques the agent demonstrated or the user confirmed they want used
- Decisions made that affect future work
- Relationships between the user and other people or systems
- Corrections the user made to prior agent assumptions

WHAT NOT TO EXTRACT:
- Ephemeral task outputs (drafts, code that was written, summaries of content)
- Questions that were asked but not answered
- Small-talk or greetings
- Anything that is only relevant to this specific session

MEMORY TYPES (choose the best fit):
- "profile"      — facts about the user's identity, role, or background
- "episodic"     — a specific event or decision that happened in this session
- "skill"        — a technique, pattern, or best practice
- "preference"   — an explicit user preference or standing instruction
- "relationship" — information about a person or system the user interacts with
- "custom"       — anything that doesn't fit the above

For episodic items that are time-sensitive, set expiresAt to an ISO timestamp ~30 days from now.
For all other types, omit expiresAt.

Respond ONLY with a JSON array. No markdown, no explanation. Example format:
[
  {
    "type": "preference",
    "summary": "User prefers TypeScript with strict mode enabled for all new projects.",
    "confidenceScore": 0.92,
    "dependencyRefs": [],
    "expiresAt": null
  }
]`;
}

/**
 * Build the user message containing the transcript for the extraction call.
 * Formats the transcript as a readable conversation block.
 */
export function buildExtractionUserMessage(transcript: TranscriptMessage[]): string {
  const formatted = transcript
    .map((msg) => `${msg.role.toUpperCase()}: ${msg.content.trim()}`)
    .join("\n\n");

  return `Here is the conversation transcript to extract memories from:\n\n---\n${formatted}\n---\n\nExtract the most important memory items as a JSON array.`;
}

// ─── Raw Claude response type (before validation) ─────────────────────────────

interface RawExtractedItem {
  type: string;
  summary: string;
  confidenceScore: number;
  dependencyRefs?: string[];
  expiresAt?: string | null;
}

// ─── Internal: Claude API call ────────────────────────────────────────────────

async function callClaudeForExtraction(
  client: Anthropic,
  transcript: TranscriptMessage[]
): Promise<RawExtractedItem[]> {
  const response = await client.messages.create({
    model: "claude-haiku-4-5",
    max_tokens: 1024,
    system: buildExtractionSystemPrompt(),
    messages: [
      {
        role: "user",
        content: buildExtractionUserMessage(transcript)
      }
    ]
  });

  const textBlock = (response.content as Array<{ type: string; text?: string }>).find(
    (b) => b.type === "text"
  );
  if (!textBlock || textBlock.type !== "text" || typeof textBlock.text !== "string") {
    throw new Error("memory-extraction: Claude returned no text block");
  }

  // Strip markdown code fences if Claude wrapped the JSON despite instructions
  const raw = textBlock.text
    .trim()
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/, "");

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`memory-extraction: failed to parse Claude JSON response: ${(err as Error).message}\nRaw: ${raw.slice(0, 200)}`);
  }

  if (!Array.isArray(parsed)) {
    throw new Error("memory-extraction: Claude response was not a JSON array");
  }

  return parsed as RawExtractedItem[];
}

// ─── Internal: Candidate assembly ────────────────────────────────────────────

const VALID_EXTRACTION_TYPES = new Set<ExtractionMemoryType>([
  "profile", "episodic", "skill", "preference", "relationship", "custom"
]);

function isValidExtractionType(v: string): v is ExtractionMemoryType {
  return VALID_EXTRACTION_TYPES.has(v as ExtractionMemoryType);
}

function sha256hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function generateUuid(): string {
  const bytes = randomBytes(16);
  // RFC 4122 v4 UUID
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32)
  ].join("-");
}

/**
 * Assemble CandidateMemoryItems from Claude's raw output.
 * Scores each item using scoreSalience() against the existing vault contents.
 * Validates and normalises all fields; falls back to heuristic classifier for bad type values.
 *
 * The segmentPositionFraction for scoring is computed as the item's array index
 * divided by total items — items earlier in Claude's array are treated as higher-priority
 * (Claude naturally lists more salient items first).
 */
function assembleCandidate(
  raw: RawExtractedItem,
  index: number,
  total: number,
  sessionId: string,
  vaultSummaries: string[],
  weights: SalienceWeights,
  proposedAt: string
): CandidateMemoryItem {
  // Validate/normalise type
  const rawType = typeof raw.type === "string" ? raw.type.toLowerCase().trim() : "";
  const extractionType: ExtractionMemoryType = isValidExtractionType(rawType)
    ? rawType
    : classifyMemoryType(raw.summary ?? "");

  // Validate summary
  const summary = typeof raw.summary === "string" && raw.summary.trim().length > 0
    ? raw.summary.trim()
    : "No summary provided";

  // Validate confidence (Claude may return values outside [0,1])
  const rawConf = typeof raw.confidenceScore === "number" ? raw.confidenceScore : 0.5;
  const confidenceScore = Math.max(0, Math.min(1, rawConf));

  // Validate dependencyRefs — Claude returns UUIDs from prior items; these are
  // positional indices in this response, not real UUIDs yet. We resolve them
  // after assigning UUIDs in the pipeline (pass empty array initially).
  const dependencyRefs: string[] = [];

  // Validate expiresAt
  let expiresAt: string | undefined;
  if (raw.expiresAt && typeof raw.expiresAt === "string") {
    const d = new Date(raw.expiresAt);
    if (!isNaN(d.getTime())) expiresAt = d.toISOString();
  }

  // segmentPositionFraction: treat Claude's list order as recency proxy
  // (index 0 = most salient/recent ≈ position 1.0)
  const segmentPositionFraction = total > 1 ? 1.0 - index / (total - 1) : 1.0;

  const salienceScore = scoreSalience(
    { segment: summary, segmentPositionFraction, existingVaultSummaries: vaultSummaries },
    weights
  );

  return {
    uuid: generateUuid(),
    type: extractionType,
    summary,
    confidenceScore,
    salienceScore,
    proposedAt,
    sourceSessionId: sessionId,
    dependencyRefs,
    expiresAt
  };
}

// ─── Internal: Deduplication ──────────────────────────────────────────────────

/**
 * Remove near-duplicate candidates from the assembled list.
 * Two items are considered duplicates if their Jaccard similarity exceeds 0.55.
 * Keeps the item with the higher salienceScore.
 */
function deduplicateCandidates(items: CandidateMemoryItem[]): CandidateMemoryItem[] {
  const kept: CandidateMemoryItem[] = [];
  for (const candidate of items) {
    const candidateWords = wordSet(candidate.summary);
    const isDuplicate = kept.some((k) => {
      const kWords = wordSet(k.summary);
      return jaccardSimilarity(candidateWords, kWords) > 0.55;
    });
    if (!isDuplicate) kept.push(candidate);
  }
  return kept;
}

// ─── 3. Write-back Pipeline ───────────────────────────────────────────────────

/**
 * Run the full memory extraction pipeline for a completed session.
 *
 * Steps:
 *   1. Call Claude haiku with the extraction prompt and full transcript
 *   2. Assemble CandidateMemoryItems, scoring each with scoreSalience()
 *   3. Filter by salienceThreshold
 *   4. Deduplicate near-identical items
 *   5. Sort descending by salienceScore
 *   6. Clamp to [3, 7] items
 *
 * Returns an array of CandidateMemoryItems ready for the caller to write
 * into the AgentMemoryVault (caller decides layer: operational-cache vs persistent-vault).
 *
 * Throws if the Claude API call fails or returns unparseable output.
 */
export async function runMemoryExtraction(
  transcript: TranscriptMessage[],
  config: ExtractionConfig
): Promise<CandidateMemoryItem[]> {
  if (transcript.length === 0) return [];

  const {
    apiKey,
    sessionId,
    vault,
    salienceThreshold = 0.35,
    maxItems = 7,
    weights: weightOverrides
  } = config;

  const weights: SalienceWeights = { ...DEFAULT_SALIENCE_WEIGHTS, ...weightOverrides };
  const clampedMax = Math.max(3, Math.min(7, maxItems));
  const proposedAt = new Date().toISOString();

  // Build vault summaries list for Novelty scoring
  const vaultSummaries: string[] = [
    ...vault.operationalCache.map((e) => e.summary),
    ...vault.persistentEntries.map((e) => e.summary),
    ...vault.verifiedEntries.map((e) => e.summary)
  ];

  // Step 1: call Claude
  const client = new Anthropic({ apiKey });
  const rawItems = await callClaudeForExtraction(client, transcript);

  if (rawItems.length === 0) return [];

  // Step 2: assemble candidates with salience scores
  const candidates = rawItems.map((raw, i) =>
    assembleCandidate(raw, i, rawItems.length, sessionId, vaultSummaries, weights, proposedAt)
  );

  // Step 3: filter by threshold
  const aboveThreshold = candidates.filter((c) => c.salienceScore >= salienceThreshold);

  // Step 4: deduplicate
  const deduped = deduplicateCandidates(aboveThreshold);

  // Step 5: sort descending
  deduped.sort((a, b) => b.salienceScore - a.salienceScore);

  // Step 6: clamp. If fewer than 3 survive threshold, relax and take top-3 from all candidates.
  if (deduped.length < 3) {
    const fallback = deduplicateCandidates(
      [...candidates].sort((a, b) => b.salienceScore - a.salienceScore)
    );
    return fallback.slice(0, 3);
  }

  return deduped.slice(0, clampedMax);
}

// ─── Vault Write Helper ───────────────────────────────────────────────────────

/**
 * Convert a CandidateMemoryItem into a MemoryEntry for vault insertion.
 *
 * Layer assignment:
 *   - episodic items → "operational-cache" (time-bound, may expire)
 *   - all other types → "persistent-vault"
 *
 * The fingerprint is a SHA-256 of the summary text, used for deduplication
 * at the vault level (matches the dedupeFingerprint pattern in VerifiedMemorySchema).
 */
export function candidateToVaultEntry(
  candidate: CandidateMemoryItem,
  vaultId: string,
  instanceId: string
): MemoryEntry {
  const now = new Date().toISOString();
  return {
    entryId: candidate.uuid,
    vaultId,
    instanceId,
    layer: candidate.type === "episodic" ? "operational-cache" : "persistent-vault",
    type: toVaultType(candidate.type),
    summary: candidate.summary,
    fingerprint: sha256hex(candidate.summary),
    tags: [candidate.type, `session:${candidate.sourceSessionId}`],
    createdAt: candidate.proposedAt,
    updatedAt: now
  };
}
