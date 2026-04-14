import { SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2.49.4";

export interface TenantContext {
  tenantId: string;
  tenantName: string;
  tier: string;
  userId: string;
}

export async function getTenantContext(supabase: SupabaseClient): Promise<TenantContext | null> {
  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) return null;
  const tenantId = user.user_metadata?.tenant_id;
  if (!tenantId) return null;
  const { data: tenant } = await supabase
    .from("tenants").select("id, name, tier")
    .eq("id", tenantId).eq("is_active", true).single();
  if (!tenant) return null;
  return { tenantId: tenant.id, tenantName: tenant.name, tier: tenant.tier, userId: user.id };
}
