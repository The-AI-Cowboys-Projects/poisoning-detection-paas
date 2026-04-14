import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import {
  getSupabaseClient,
  getServiceClient,
  jsonResponse,
  errorResponse,
  corsHeaders,
} from "../_shared/supabase-client.ts";
import { getTenantContext } from "../_shared/tenant-auth.ts";

// ---------------------------------------------------------------------------
// Route helpers
// ---------------------------------------------------------------------------

function pathEndsWith(pathname: string, suffix: string): boolean {
  return pathname.endsWith(suffix);
}

function pathContains(pathname: string, segment: string): boolean {
  return pathname.includes(segment);
}

function extractPathSegmentAfter(pathname: string, segment: string): string | null {
  const idx = pathname.indexOf(segment);
  if (idx === -1) return null;
  const after = pathname.slice(idx + segment.length).replace(/^\//, "");
  return after || null;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const supabase = getSupabaseClient(req);
  const tenant = await getTenantContext(supabase);
  if (!tenant) return errorResponse("Unauthorized", 401);

  const service = getServiceClient();
  const url = new URL(req.url);
  const pathname = url.pathname;
  const method = req.method;

  // -------------------------------------------------------------------------
  // POST /provenance/nodes — insert a provenance node
  // -------------------------------------------------------------------------
  if (method === "POST" && pathEndsWith(pathname, "/nodes")) {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return errorResponse("Invalid JSON body", 400);
    }

    const { node_id, node_type, label, attributes } = body as {
      node_id?: string;
      node_type?: string;
      label?: string;
      attributes?: Record<string, unknown>;
    };

    if (!node_type) return errorResponse("node_type is required", 400);
    if (!label) return errorResponse("label is required", 400);

    const { data, error } = await service
      .from("provenance_nodes")
      .insert({
        id: node_id ?? undefined,
        tenant_id: tenant.tenantId,
        node_type,
        label,
        attributes: attributes ?? {},
        created_by: tenant.userId,
      })
      .select()
      .single();

    if (error) {
      console.error("provenance_nodes insert error:", error);
      return errorResponse(`Failed to insert provenance node: ${error.message}`, 500);
    }

    return jsonResponse({ node: data }, 201);
  }

  // -------------------------------------------------------------------------
  // POST /provenance/edges — insert a provenance edge
  // -------------------------------------------------------------------------
  if (method === "POST" && pathEndsWith(pathname, "/edges")) {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return errorResponse("Invalid JSON body", 400);
    }

    const { source_id, target_id, edge_type, weight, attributes } = body as {
      source_id?: string;
      target_id?: string;
      edge_type?: string;
      weight?: number;
      attributes?: Record<string, unknown>;
    };

    if (!source_id) return errorResponse("source_id is required", 400);
    if (!target_id) return errorResponse("target_id is required", 400);
    if (!edge_type) return errorResponse("edge_type is required", 400);

    const { data, error } = await service
      .from("provenance_edges")
      .insert({
        tenant_id: tenant.tenantId,
        source_id,
        target_id,
        edge_type,
        weight: weight ?? 1.0,
        attributes: attributes ?? {},
        created_by: tenant.userId,
      })
      .select()
      .single();

    if (error) {
      console.error("provenance_edges insert error:", error);
      return errorResponse(`Failed to insert provenance edge: ${error.message}`, 500);
    }

    return jsonResponse({ edge: data }, 201);
  }

  // -------------------------------------------------------------------------
  // GET /provenance/lineage/:node_id — get full lineage for a node
  // -------------------------------------------------------------------------
  if (method === "GET" && pathContains(pathname, "/lineage/")) {
    const nodeId = extractPathSegmentAfter(pathname, "/lineage/");
    if (!nodeId) return errorResponse("node_id is required in path", 400);

    const maxDepth = parseInt(url.searchParams.get("max_depth") ?? "10", 10);
    const direction = (url.searchParams.get("direction") ?? "both") as "upstream" | "downstream" | "both";

    const { data, error } = await service.rpc("get_provenance_lineage", {
      p_tenant_id: tenant.tenantId,
      p_node_id: nodeId,
      p_max_depth: maxDepth,
      p_direction: direction,
    });

    if (error) {
      console.error("get_provenance_lineage RPC error:", error);
      return errorResponse(`Failed to retrieve lineage: ${error.message}`, 500);
    }

    return jsonResponse({
      node_id: nodeId,
      direction,
      max_depth: maxDepth,
      lineage: data,
    });
  }

  // -------------------------------------------------------------------------
  // GET /provenance/blast-radius/:node_id — contamination blast radius
  // -------------------------------------------------------------------------
  if (method === "GET" && pathContains(pathname, "/blast-radius/")) {
    const nodeId = extractPathSegmentAfter(pathname, "/blast-radius/");
    if (!nodeId) return errorResponse("node_id is required in path", 400);

    const { data, error } = await service.rpc("get_contamination_blast_radius", {
      p_tenant_id: tenant.tenantId,
      p_source_node_id: nodeId,
    });

    if (error) {
      console.error("get_contamination_blast_radius RPC error:", error);
      return errorResponse(`Failed to compute blast radius: ${error.message}`, 500);
    }

    return jsonResponse({
      source_node_id: nodeId,
      blast_radius: data,
    });
  }

  // -------------------------------------------------------------------------
  // POST /provenance/flag — flag a node as contaminated
  // -------------------------------------------------------------------------
  if (method === "POST" && pathEndsWith(pathname, "/flag")) {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return errorResponse("Invalid JSON body", 400);
    }

    const { node_id, contamination_type, severity, reason } = body as {
      node_id?: string;
      contamination_type?: string;
      severity?: string;
      reason?: string;
    };

    if (!node_id) return errorResponse("node_id is required", 400);
    if (!contamination_type) return errorResponse("contamination_type is required", 400);

    const { data, error } = await service.rpc("flag_contamination", {
      p_tenant_id: tenant.tenantId,
      p_node_id: node_id,
      p_contamination_type: contamination_type,
      p_severity: severity ?? "medium",
      p_reason: reason ?? null,
      p_flagged_by: tenant.userId,
    });

    if (error) {
      console.error("flag_contamination RPC error:", error);
      return errorResponse(`Failed to flag contamination: ${error.message}`, 500);
    }

    return jsonResponse({
      node_id,
      contamination_type,
      severity: severity ?? "medium",
      flag_result: data,
    });
  }

  // -------------------------------------------------------------------------
  // Fallthrough
  // -------------------------------------------------------------------------
  return errorResponse(
    `No matching route for ${method} ${pathname}. Valid routes: POST /nodes, POST /edges, GET /lineage/:id, GET /blast-radius/:id, POST /flag`,
    404
  );
});
