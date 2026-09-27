import { NextRequest, NextResponse } from 'next/server'
import { cookies } from 'next/headers'
import crypto from 'crypto'
import { pool } from '@/lib/db'
const hash = (value: string) => crypto.createHash('sha256').update(value).digest('hex')
async function userId() { const token = (await cookies()).get('app_session')?.value; if (!token) return null; const r = await pool.query('SELECT user_id FROM app_sessions WHERE token_hash=$1 AND expires_at>now()', [hash(token)]); return r.rows[0]?.user_id ?? null }
export async function GET() { const id = await userId(); if (!id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 }); const r = await pool.query('SELECT streak_days,completed_lessons,weekly_goal FROM app_user_progress WHERE user_id=$1', [id]); return NextResponse.json(r.rows[0] ?? { streak_days: 0, completed_lessons: 0, weekly_goal: 5 }) }
export async function PATCH(request: NextRequest) { const id = await userId(); if (!id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 }); const body = await request.json(); const completed = Math.max(0, Number(body.completedLessons) || 0); const streak = Math.max(0, Number(body.streakDays) || 0); await pool.query('INSERT INTO app_user_progress(user_id,completed_lessons,streak_days,updated_at) VALUES($1,$2,$3,now()) ON CONFLICT(user_id) DO UPDATE SET completed_lessons=$2,streak_days=$3,updated_at=now()', [id, completed, streak]); return NextResponse.json({ ok: true }) }
