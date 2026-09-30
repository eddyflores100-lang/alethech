import type { PortablePayload, VerifiedPortableView } from "./portable-verifier.ts";
import { verifyPortablePayload } from "./portable-verifier.ts";
import { toAlethechContext, type ContextSelectionOptions } from "./context-adapter.ts";
import { createChatEnvelope, type AlethechWritebackProposal } from "./chat-adapter-contract.ts";
import {
  toAnthropicCompatibleRequest,
  toLocalAgentRequest,
  toOpenAICompatibleRequest,
  writebackProposalFromProviderJson,
  type AnthropicCompatibleRequest,
  type LocalAgentRequest,
  type OpenAICompatibleRequest,
} from "./provider-bridges.ts";
import { acceptWritebackProposal } from "./provider-writeback.ts";

export type PluginProviderKind = "openai" | "anthropic" | "local";

export interface AlethechPluginSession {
  payload: PortablePayload;
  view: VerifiedPortableView;
}

export type PreparedProviderRequest =
  | OpenAICompatibleRequest
  | AnthropicCompatibleRequest
  | LocalAgentRequest;

export async function createPluginSession(payload: PortablePayload): Promise<AlethechPluginSession> {
  const view = await verifyPortablePayload(payload);
  return { payload: structuredClone(payload), view };
}

export function preparePluginRequest(
  session: AlethechPluginSession,
  provider: PluginProviderKind,
  userInput: string,
  options: ContextSelectionOptions = {},
): PreparedProviderRequest {
  const context = toAlethechContext(session.view, options);
  const envelope = createChatEnvelope(context);
  if (provider === "openai") return toOpenAICompatibleRequest(envelope, userInput);
  if (provider === "anthropic") return toAnthropicCompatibleRequest(envelope, userInput);
  return toLocalAgentRequest(envelope, userInput);
}

export function reviewPluginWriteback(
  session: AlethechPluginSession,
  providerResponseText: string,
): AlethechWritebackProposal {
  return writebackProposalFromProviderJson(session.view.head, providerResponseText);
}

/**
 * Explicit local acceptance boundary.
 *
 * Callers should only invoke this after a user-visible approval action.
 * The provider proposal remains unsigned until this function creates local
 * Ed25519-signed MemoryCommit objects and reverifies the complete history.
 */
export async function acceptPluginWriteback(
  session: AlethechPluginSession,
  proposal: AlethechWritebackProposal,
): Promise<AlethechPluginSession> {
  const accepted = await acceptWritebackProposal(session.payload, proposal);
  return { payload: accepted.payload, view: accepted.view };
}
