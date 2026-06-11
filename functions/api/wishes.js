// Cloudflare Pages Function: /api/wishes
// Bindings cần có: DB (D1 database), ADMIN_KEY (secret/env var)

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });

// Lấy IP để rate-limit
function clientIP(req) {
  return req.headers.get('CF-Connecting-IP') || 'unknown';
}

// GET: trả danh sách lời chúc (mới nhất trước)
export async function onRequestGet({ env }) {
  const { results } = await env.DB.prepare(
    'SELECT id, name, message FROM wishes ORDER BY created_at DESC LIMIT 500'
  ).all();
  return json({ wishes: results || [] });
}

// POST: thêm lời chúc mới (có chặn bot)
export async function onRequestPost({ request, env }) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Dữ liệu không hợp lệ' }, 400); }

  // 1) Honeypot: bot điền vào field ẩn -> giả vờ thành công, không lưu
  if (body.hp) return json({ ok: true });

  let name = (body.name || '').toString().trim();
  let message = (body.message || '').toString().trim();

  // 2) Validate độ dài
  if (name.length < 2 || name.length > 40) return json({ error: 'Tên không hợp lệ' }, 400);
  if (message.length < 2 || message.length > 280) return json({ error: 'Lời chúc quá ngắn hoặc quá dài' }, 400);

  // 3) Chặn link (spam quảng cáo thường nhét URL)
  if (/https?:\/\/|www\.|\.(com|net|xyz|vn|info|top)\b/i.test(message)) {
    return json({ error: 'Lời chúc không được chứa đường link' }, 400);
  }

  const ip = clientIP(request);

  // 4) Rate limit: tối đa 5 lời chúc / IP / 10 phút
  const since = Date.now() - 10 * 60 * 1000;
  const cnt = await env.DB.prepare(
    'SELECT COUNT(*) AS c FROM wishes WHERE ip = ? AND created_at > ?'
  ).bind(ip, since).first();
  if (cnt && cnt.c >= 5) {
    return json({ error: 'Bạn gửi hơi nhanh, thử lại sau ít phút nhé' }, 429);
  }

  // 5) Chống trùng lặp y hệt trong 1 phút (double-submit / bot)
  const dupSince = Date.now() - 60 * 1000;
  const dup = await env.DB.prepare(
    'SELECT id FROM wishes WHERE message = ? AND created_at > ? LIMIT 1'
  ).bind(message, dupSince).first();
  if (dup) return json({ ok: true }); // im lặng

  await env.DB.prepare(
    'INSERT INTO wishes (name, message, ip, created_at) VALUES (?, ?, ?, ?)'
  ).bind(name, message, ip, Date.now()).run();

  return json({ ok: true });
}

// DELETE: xoá lời chúc (chỉ admin)
export async function onRequestDelete({ request, env }) {
  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  const key = url.searchParams.get('admin');

  if (!env.ADMIN_KEY || key !== env.ADMIN_KEY) {
    return json({ error: 'Không có quyền' }, 403);
  }
  if (!id) return json({ error: 'Thiếu id' }, 400);

  await env.DB.prepare('DELETE FROM wishes WHERE id = ?').bind(id).run();
  return json({ ok: true });
}
