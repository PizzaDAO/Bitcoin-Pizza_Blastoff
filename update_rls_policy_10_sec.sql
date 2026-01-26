-- ENHANCED RLS policy with session verification to prevent leaderboard spam
-- This prevents attackers from submitting fake scores with fabricated session data
-- Run this in your Supabase SQL Editor

DROP POLICY IF EXISTS "heartbeat_validated_inserts" ON leaderboard;

CREATE POLICY "heartbeat_validated_inserts" ON leaderboard 
FOR INSERT TO public 
WITH CHECK (
  -- Basic score validation
  score >= 0 AND
  
  -- Player name validation (1-30 chars, no XSS attempts)
  LENGTH(player_name) BETWEEN 1 AND 30 AND
  player_name !~ '<|>|script|href|onclick' AND
  
  -- Session must exist
  session_id IS NOT NULL AND
  
  -- Heartbeat count must be non-negative
  heartbeat_count >= 0 AND
  
  -- Game must have lasted at least 10 seconds
  session_duration >= 10 AND
  
  -- Heartbeat math validation (10-second intervals, allow 30 second tolerance)
  -- Expected: heartbeat_count * 10 ≈ session_duration
  ABS(session_duration - (heartbeat_count * 10)) <= 30 AND
  
  -- Physics-based score cap (30 points per second max)
  score <= (session_duration * 30) AND
  
  -- 🔒 NEW: Verify session actually exists in game_sessions table
  EXISTS (
    SELECT 1 FROM game_sessions 
    WHERE id = session_id
  ) AND
  
  -- 🔒 NEW: Verify heartbeat count matches what's recorded in the session
  EXISTS (
    SELECT 1 FROM game_sessions 
    WHERE id = session_id 
    AND heartbeat_count = leaderboard.heartbeat_count
  ) AND
  
  -- 🔒 NEW: Verify session isn't too old (max 4 hours gameplay = 14400 seconds)
  -- This prevents reusing old session IDs
  EXISTS (
    SELECT 1 FROM game_sessions 
    WHERE id = session_id 
    AND created_at >= NOW() - INTERVAL '4 hours'
  ) AND
  
  -- 🔒 NEW: Maximum reasonable gameplay duration (4 hours = 14400 seconds)
  session_duration <= 14400 AND
  
  -- 🔒 NEW: Prevent duplicate submissions for the same session
  NOT EXISTS (
    SELECT 1 FROM leaderboard 
    WHERE session_id = leaderboard.session_id
  )
);

-- Also add rate limiting: max 10 submissions per player per hour
DROP POLICY IF EXISTS "rate_limit_submissions" ON leaderboard;

CREATE POLICY "rate_limit_submissions" ON leaderboard
FOR INSERT TO public
WITH CHECK (
  -- Count recent submissions from this player name in the last hour
  (
    SELECT COUNT(*) 
    FROM leaderboard 
    WHERE player_name = leaderboard.player_name 
    AND created_at >= NOW() - INTERVAL '1 hour'
  ) < 10
);

-- Verify the policies
SELECT 'RLS Policies Updated Successfully - Leaderboard Now Protected' as status;

-- Optional: Clean up existing spam entries
-- Uncomment the following lines to delete flagged entries:
-- DELETE FROM leaderboard WHERE flagged = true;
-- SELECT 'Spam entries cleaned up' as cleanup_status;
