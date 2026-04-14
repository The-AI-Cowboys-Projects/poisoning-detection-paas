import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import {
  getSupabaseClient,
  getServiceClient,
  jsonResponse,
  errorResponse,
  corsHeaders,
} from "../_shared/supabase-client.ts";
import { getTenantContext } from "../_shared/tenant-auth.ts";

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "GET") {
    return errorResponse("Method not allowed", 405);
  }

  const supabase = getSupabaseClient(req);
  const tenant = await getTenantContext(supabase);
  if (!tenant) return errorResponse("Unauthorized", 401);

  const service = getServiceClient();

  // Parse optional query params for time window
  const url = new URL(req.url);
  const days = parseInt(url.searchParams.get("days") ?? "7", 10);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  // Run all four RPC calls in parallel for performance
  const [summaryResult, timelineResult, threatResult, alertsResult] = await Promise.all([
    service.rpc("get_dashboard_summary", {
      p_tenant_id: tenant.tenantId,
    }),
    service.rpc("get_dashboard_timeline", {
      p_tenant_id: tenant.tenantId,
      p_days: days,
    }),
    service.rpc("get_threat_breakdown", {
      p_tenant_id: tenant.tenantId,
    }),
    service.rpc("get_recent_alerts", {
      p_tenant_id: tenant.tenantId,
      p_limit: 20,
    }),
  ]);

  // Collect any RPC errors but still return partial data
  const errors: Record<string, string> = {};
  if (summaryResult.error) {
    console.error("get_dashboard_summary error:", summaryResult.error);
    errors.summary = summaryResult.error.message;
  }
  if (timelineResult.error) {
    console.error("get_dashboard_timeline error:", timelineResult.error);
    errors.timeline = timelineResult.error.message;
  }
  if (threatResult.error) {
    console.error("get_threat_breakdown error:", threatResult.error);
    errors.threat_breakdown = threatResult.error.message;
  }
  if (alertsResult.error) {
    console.error("get_recent_alerts error:", alertsResult.error);
    errors.recent_alerts = alertsResult.error.message;
  }

  return jsonResponse({
    tenant_id: tenant.tenantId,
    tenant_name: tenant.tenantName,
    tier: tenant.tier,
    window: { days, since },
    summary: summaryResult.data ?? null,
    timeline: timelineResult.data ?? null,
    threat_breakdown: threatResult.data ?? null,
    recent_alerts: alertsResult.data ?? null,
    ...(Object.keys(errors).length > 0 ? { partial_errors: errors } : {}),
  });
});
