import { describe, expect, test } from "bun:test";
import type { SessionFrame } from "../src/core/session";
import {
  BridgeFailure,
  McpBridge,
  RpcClient,
  RpcServer,
  allowAllEnforcer,
  callMcpTool,
  contractToMcpTools,
  mcpToContractActions,
  type AgentContract,
  type McpToolList,
  type RpcTransport,
} from "../src/index";

function makePipe(): { client: RpcTransport; server: RpcTransport } {
  const clientListeners = new Set<(f: SessionFrame) => void>();
  const serverListeners = new Set<(f: SessionFrame) => void>();
  return {
    client: {
      send: (f) => serverListeners.forEach((l) => l(f)),
      onFrame: (l) => clientListeners.add(l),
    },
    server: {
      send: (f) => clientListeners.forEach((l) => l(f)),
      onFrame: (l) => serverListeners.add(l),
    },
  };
}

describe("MCP bridge projection", () => {
  test("imports an MCP tool list into contract actions", () => {
    const tools: McpToolList = {
      tools: [
        {
          name: "fs_read_file",
          description: "Read a file from the working tree.",
          inputSchema: {
            type: "object",
            required: ["path"],
            properties: { path: { type: "string" } },
          },
        },
        {
          name: "shell.exec",
          description: "Execute a command.",
        },
      ],
    };
    const actions = mcpToContractActions(tools, {
      defaultRisk: "R2",
      defaultApproval: "conditional",
      namePrefix: "mcp",
      dangerTagMap: { "shell.exec": ["destructive", "security-sensitive"] },
    });
    expect(actions).toHaveLength(2);
    expect(actions[0]!.name).toBe("mcp.fs_read_file");
    expect(actions[0]!.parameters).toEqual(tools.tools[0]!.inputSchema);
    expect(actions[0]!.risk).toBe("R2");
    expect(actions[1]!.name).toBe("mcp.shell_exec");
    expect(actions[1]!.danger_tags).toEqual(["destructive", "security-sensitive"]);
  });

  test("rejects MCP tools missing a name", () => {
    expect(() =>
      mcpToContractActions({ tools: [{ name: "" }] } as McpToolList),
    ).toThrow(BridgeFailure);
  });

  test("exports contract actions back into an MCP tool list with danger warning", () => {
    const contract: AgentContract = {
      contract_version: "1",
      spec_version: "TF-0006-draft",
      project: "demo",
      actions: [
        {
          name: "file.write",
          risk: "R2",
          approval: "conditional",
          reversible: false,
          danger_tags: ["destructive"],
          description: "Write a file.",
          parameters: {
            type: "object",
            required: ["path"],
            properties: { path: { type: "string" } },
          },
        },
      ],
    };
    const projected = contractToMcpTools(contract);
    expect(projected.tools).toHaveLength(1);
    expect(projected.tools[0]!.name).toBe("file.write");
    expect(projected.tools[0]!.description).toContain("⚠️");
    expect(projected.tools[0]!.description).toContain("destructive");
    expect(projected.tools[0]!.inputSchema).toEqual(contract.actions![0]!.parameters as Record<string, unknown>);
  });
});

describe("callMcpTool integration", () => {
  test("dispatches to the matching RPC method", async () => {
    const pipe = makePipe();
    const server = new RpcServer(pipe.server, {
      selfActor: "tf:actor:service:example.com/srv",
      enforcer: allowAllEnforcer,
    });
    server.registerUnary<{ path: string }, { echo: string }>(
      "mcp.fs_read_file",
      "mcp.fs_read_file",
      async (req) => ({ echo: `read:${req.path}` }),
    );
    const rpc = new RpcClient(pipe.client, { callerActor: "tf:actor:agent:example.com/cli" });
    const response = await callMcpTool<{ path: string }, { echo: string }>(
      rpc,
      "fs_read_file",
      { path: "README.md" },
      { namePrefix: "mcp" },
    );
    expect(response.echo).toBe("read:README.md");
  });

  test("McpBridge class exposes importTools / exportTools / call", async () => {
    const bridge = new McpBridge("tf-mcp-bridge", "example.com", {
      bridgeId: "tf-mcp-bridge",
      defaultRisk: "R1",
      defaultApproval: "none",
      namePrefix: "mcp",
    });
    const tools: McpToolList = {
      tools: [{ name: "ping", description: "Ping" }],
    };
    const actions = bridge.importTools(tools);
    expect(actions[0]!.name).toBe("mcp.ping");
    expect(actions[0]!.risk).toBe("R1");
    expect(actions[0]!.approval).toBe("none");
    const back = bridge.exportTools({
      contract_version: "1",
      spec_version: "TF-0006-draft",
      project: "demo",
      actions,
    });
    expect(back.tools[0]!.name).toBe("mcp.ping");
  });
});
