import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const SUPER_ADMIN_ID = "0a88c330-e26d-462b-a914-62b17a8dc06f";
const BAN_DURATION = "876000h";

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method tidak diizinkan." }, 405);

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    return json({ error: "Konfigurasi server Supabase belum lengkap." }, 500);
  }

  const authHeader = req.headers.get("Authorization") || "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (!token) return json({ error: "Sesi login tidak ditemukan." }, 401);

  const callerClient = createClient(supabaseUrl, anonKey, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { Authorization: `Bearer ${token}` } },
  });
  const { data: callerData, error: callerError } = await callerClient.auth.getUser(token);
  if (callerError || !callerData.user || callerData.user.id !== SUPER_ADMIN_ID) {
    return json({ error: "Akses ditolak. Fitur ini hanya untuk Super Admin." }, 403);
  }

  const admin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  let body: { action?: string; user_id?: string };
  try {
    body = await req.json();
  } catch {
    return json({ error: "Format permintaan tidak valid." }, 400);
  }

  if (body.action === "list") {
    const [{ data: profiles, error: profilesError }, { data: memberships, error: membershipsError }] =
      await Promise.all([
        admin.from("profiles").select("id,username,created_at"),
        admin.from("anggota_kelompok").select("user_id"),
      ]);
    if (profilesError) return json({ error: profilesError.message }, 500);
    if (membershipsError) return json({ error: membershipsError.message }, 500);

    const memberIds = new Set((memberships || []).map((m) => m.user_id));
    const candidates = (profiles || []).filter((p) =>
      p.id !== SUPER_ADMIN_ID && !memberIds.has(p.id)
    );

    const authUsers = [];
    for (let page = 1; page <= 100; page++) {
      const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 1000 });
      if (error) return json({ error: error.message }, 500);
      authUsers.push(...(data.users || []));
      if (!data.users || data.users.length < 1000) break;
    }

    const usersById = new Map(authUsers.map((u) => [u.id, u]));
    const result = candidates.map((p) => {
      const authUser = usersById.get(p.id);
      const bannedUntil = authUser?.banned_until || null;
      const isDisabled = !!bannedUntil && new Date(bannedUntil).getTime() > Date.now();
      return {
        id: p.id,
        username: p.username || "Tanpa username",
        email: authUser?.email || "",
        created_at: p.created_at,
        disabled: isDisabled,
        banned_until: bannedUntil,
      };
    }).filter((p) => usersById.has(p.id));

    return json({ users: result });
  }

  if (!["disable", "enable"].includes(body.action || "") || !body.user_id) {
    return json({ error: "Aksi atau ID akun tidak valid." }, 400);
  }
  if (body.user_id === SUPER_ADMIN_ID) {
    return json({ error: "Akun Super Admin tidak dapat dinonaktifkan." }, 400);
  }

  const { data: membership, error: membershipError } = await admin
    .from("anggota_kelompok")
    .select("user_id")
    .eq("user_id", body.user_id)
    .maybeSingle();
  if (membershipError) return json({ error: membershipError.message }, 500);
  if (membership) {
    return json({ error: "Akun sudah tergabung dalam kelompok. Keluarkan dari kelompok terlebih dahulu." }, 409);
  }

  const { data: target, error: targetError } = await admin.auth.admin.getUserById(body.user_id);
  if (targetError || !target.user) return json({ error: "Akun tidak ditemukan." }, 404);

  const ban_duration = body.action === "disable" ? BAN_DURATION : "none";
  const { error: updateError } = await admin.auth.admin.updateUserById(body.user_id, { ban_duration });
  if (updateError) return json({ error: updateError.message }, 500);

  return json({
    success: true,
    action: body.action,
    message: body.action === "disable"
      ? "Akun berhasil dinonaktifkan."
      : "Akun berhasil diaktifkan kembali.",
  });
});
