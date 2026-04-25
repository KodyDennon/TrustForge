/**
 * MCP bridge — project an MCP tool list to a TrustForge agent-contract
 * actions array and back, plus a thin helper that calls an MCP tool
 * through an RpcClient.
 *
 * The bridge does not speak MCP JSON-RPC itself. It only translates the
 * typed shape so AI agents discovering an MCP endpoint can materialise
 * the same contract guarantees as those discovering .tf/agent-contract.yaml.
 */

import type { Action, AgentContract } from "../generated/agent-contract.js";
import type { ApprovalRequirement, DangerTag, ProofLevel, RiskClass } from "../generated/_common.js";
import { BridgeFailure, type Bridge, type BridgeKind } from "./bridges.js";
import type { RpcClient } from "./rpc.js";

export interface McpTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface McpToolList {
  tools: McpTool[];
}

export interface McpImportOptions {
  defaultRisk?: RiskClass;
  defaultApproval?: ApprovalRequirement;
  defaultProof?: ProofLevel;
  /** Map MCP tool name → danger tags; anything matching escalates in the guard. */
  dangerTagMap?: Record<string, DangerTag[]>;
  /** Optional prefix prepended to every imported action name. */
  namePrefix?: string;
}

const ACTION_NAME_RE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;

function normalizeToolName(name: string, prefix?: string): string {
  const scrubbed = name
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toLowerCase();
  const withPrefix = prefix ? `${prefix}.${scrubbed}` : scrubbed;
  // Ensure the result has at least one dot (agent-contract ActionName
  // requires `foo.bar` shape).
  return withPrefix.includes(".") ? withPrefix : `mcp.${withPrefix}`;
}

/** Import: an MCP tool list → a partial AgentContract actions array. */
export function mcpToContractActions(
  toolList: McpToolList,
  opts: McpImportOptions = {},
): Action[] {
  if (!Array.isArray(toolList?.tools)) {
    throw new BridgeFailure({ code: "invalid-input", message: "MCP tool list missing .tools array" });
  }
  const defaultRisk = opts.defaultRisk ?? "R2";
  const defaultApproval = opts.defaultApproval ?? "conditional";
  return toolList.tools.map((tool) => {
    if (!tool.name || typeof tool.name !== "string") {
      throw new BridgeFailure({
        code: "invalid-input",
        message: "MCP tool missing a name",
      });
    }
    const actionName = normalizeToolName(tool.name, opts.namePrefix);
    if (!ACTION_NAME_RE.test(actionName)) {
      throw new BridgeFailure({
        code: "invalid-input",
        message: `MCP tool ${tool.name} produced invalid action name ${actionName}`,
      });
    }
    const dangerTags = opts.dangerTagMap?.[tool.name];
    const action: Action = {
      name: actionName,
      risk: defaultRisk,
      approval: defaultApproval,
    };
    if (opts.defaultProof) action.proof = opts.defaultProof;
    if (tool.description) action.description = tool.description;
    if (tool.inputSchema) action.parameters = tool.inputSchema;
    if (dangerTags && dangerTags.length > 0) action.danger_tags = dangerTags;
    return action;
  });
}

/** Export: an AgentContract → an MCP tool list. */
export function contractToMcpTools(contract: AgentContract): McpToolList {
  const actions = contract.actions ?? [];
  const tools: McpTool[] = actions.map((action) => {
    const dangerTags = action.danger_tags ?? [];
    const warning = dangerTags.length > 0 ? `⚠️ ${dangerTags.join(", ")}. ` : "";
    const description = `${warning}${action.description ?? ""}`.trim();
    const tool: McpTool = { name: action.name };
    if (description.length > 0) tool.description = description;
    if (action.parameters) tool.inputSchema = action.parameters;
    return tool;
  });
  return { tools };
}

/** Invoke an MCP tool via an RpcClient. The TrustForge RPC method name is
 *  the normalized action name (see normalizeToolName). */
export async function callMcpTool<Args = unknown, Result = unknown>(
  rpc: RpcClient,
  toolName: string,
  args: Args,
  opts: { namePrefix?: string } = {},
): Promise<Result> {
  const actionName = normalizeToolName(toolName, opts.namePrefix);
  return rpc.call<Args, Result>(actionName, args);
}

export interface McpBridgeConfig {
  bridgeId: string;
  defaultRisk?: RiskClass;
  defaultApproval?: ApprovalRequirement;
  dangerTagMap?: Record<string, DangerTag[]>;
  namePrefix?: string;
}

export class McpBridge implements Bridge {
  readonly kind: BridgeKind = "mcp";
  constructor(
    public readonly bridgeId: string,
    public readonly trustDomain: string,
    private readonly cfg: McpBridgeConfig,
  ) {}

  importTools(toolList: McpToolList): Action[] {
    return mcpToContractActions(toolList, this.cfg);
  }

  exportTools(contract: AgentContract): McpToolList {
    return contractToMcpTools(contract);
  }

  async call<A = unknown, R = unknown>(
    rpc: RpcClient,
    toolName: string,
    args: A,
  ): Promise<R> {
    return callMcpTool<A, R>(rpc, toolName, args, { namePrefix: this.cfg.namePrefix });
  }
}
