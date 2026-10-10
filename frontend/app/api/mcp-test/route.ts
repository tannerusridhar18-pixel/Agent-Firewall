import { NextResponse } from "next/server";

const backendUrl = process.env.BACKEND_URL || "http://127.0.0.1:8080";
const configuredMcpKey = process.env.INTENTGUARD_MCP_API_KEY || "intentguard-mcp-client-secret-key";

export async function POST(request: Request) {
  const body = await request.json() as {
    authMode?: "valid" | "invalid" | "none";
    mcpRequest?: Record<string, unknown>;
  };

  const headers = new Headers({ "Content-Type": "application/json" });
  if (body.authMode === "valid") {
    headers.set("Authorization", `Bearer ${configuredMcpKey}`);
  } else if (body.authMode === "invalid") {
    headers.set("Authorization", "Bearer invalid-test-key");
  }

  const response = await fetch(`${backendUrl}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify(body.mcpRequest ?? {}),
    cache: "no-store",
  });

  return NextResponse.json(await response.json(), { status: response.status });
}
