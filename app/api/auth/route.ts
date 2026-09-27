import { NextRequest, NextResponse } from 'next/server'
import { cookies } from 'next/headers'
import bcrypt from 'bcryptjs'
import crypto from 'crypto'
import { pool } from '@/lib/db'

const classes = /^(X|XI|XII) (E[1-9]|F[1-9]|FL[1-9])$/
const hash = (value: string) => crypto.createHash('sha256').update(value).digest('hex')
const json = (body: unknown, status = 200) => NextResponse.json(body, { status })

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}))
  const action = body.action
  if (action === 'signup') {
    const fullName = String(body.fullName ?? '').trim().replace(/\s+/g, ' ')
    const classCode = String(body.classCode ?? '').trim().toUpperCase()
    const email = String(body.email ?? '').trim().toLowerCase()
    const password = String(body.password ?? '')
    if (fullName.length < 3 || !classes.test(classCode) || !/^\S+@\S+\.\S+$/.test(email) || password.length < 8) return json({ error: 'Nama, kelas, email, dan password belum valid.' }, 400)
    const existing = await pool.query('SELECT id FROM app_users WHERE lower(full_name) = lower($1) AND class_code = $2 LIMIT 1', [fullName, classCode])
    if (existing.rowCount) return json({ error: 'Nama lengkap dan kelas tersebut sudah terdaftar.' }, 409)
    const emailTaken = await pool.query('SELECT id FROM app_users WHERE email = $1 LIMIT 1', [email])
    if (emailTaken.rowCount) return json({ error: 'Email sudah terdaftar.' }, 409)
    const otp = String(crypto.randomInt(100000, 1000000))
    await pool.query('INSERT INTO app_signup_otps(email, full_name, class_code, password_hash, otp_hash, expires_at) VALUES($1,$2,$3,$4,$5,now()+interval \'10 minutes\') ON CONFLICT(email) DO UPDATE SET full_name=$2,class_code=$3,password_hash=$4,otp_hash=$5,expires_at=now()+interval \'10 minutes\'', [email, fullName, classCode, await bcrypt.hash(password, 12), hash(otp)])
    return json({ ok: true, requiresOtp: true, devOtp: process.env.NODE_ENV === 'development' ? otp : undefined })
  }
  if (action === 'verify') {
    const email = String(body.email ?? '').trim().toLowerCase(); const otp = String(body.otp ?? '').trim()
    const pending = await pool.query('SELECT * FROM app_signup_otps WHERE email=$1 AND expires_at > now()', [email])
    if (!pending.rowCount || hash(otp) !== pending.rows[0].otp_hash) return json({ error: 'Kode OTP salah atau sudah kedaluwarsa.' }, 400)
    const p = pending.rows[0]
    const user = await pool.query('INSERT INTO app_users(full_name,class_code,email,password_hash) VALUES($1,$2,$3,$4) RETURNING id,full_name,class_code,email', [p.full_name,p.class_code,p.email,p.password_hash])
    await pool.query('INSERT INTO app_user_progress(user_id) VALUES($1) ON CONFLICT DO NOTHING', [user.rows[0].id])
    await pool.query('DELETE FROM app_signup_otps WHERE email=$1', [email])
    return createSession(user.rows[0])
  }
  if (action === 'login') {
    const email = String(body.email ?? '').trim().toLowerCase(); const password = String(body.password ?? '')
    const result = await pool.query('SELECT id,full_name,class_code,email,password_hash FROM app_users WHERE email=$1 LIMIT 1', [email])
    if (!result.rowCount || !(await bcrypt.compare(password, result.rows[0].password_hash))) return json({ error: 'Email atau password salah.' }, 401)
    await pool.query('INSERT INTO app_user_progress(user_id) VALUES($1) ON CONFLICT DO NOTHING', [result.rows[0].id])
    return createSession(result.rows[0])
  }
  if (action === 'logout') { const token = (await cookies()).get('app_session')?.value; if (token) await pool.query('DELETE FROM app_sessions WHERE token_hash=$1', [hash(token)]); const response = json({ ok: true }); response.cookies.delete('app_session'); return response }
  return json({ error: 'Aksi tidak dikenal.' }, 400)
}

async function createSession(user: { id: string; full_name: string; class_code: string; email: string }) {
  const token = crypto.randomBytes(32).toString('hex')
  await pool.query('INSERT INTO app_sessions(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval \'30 days\')', [user.id, hash(token)])
  const response = json({ ok: true, user: { id: user.id, fullName: user.full_name, classCode: user.class_code, email: user.email } })
  response.cookies.set('app_session', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 60 * 60 * 24 * 30, path: '/' })
  return response
}
