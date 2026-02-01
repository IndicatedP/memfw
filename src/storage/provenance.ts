import Database from 'better-sqlite3';
import { v4 as uuidv4 } from 'uuid';
import { TrustLevel, MemoryProvenance } from '../core/types.js';

/**
 * SQLite-based provenance store for tracking memory metadata
 */
export class ProvenanceStore {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.initSchema();
  }

  /**
   * Initialize database schema
   */
  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS provenance (
        id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        trust_level TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        session_id TEXT,
        trigger_context TEXT,
        detection_score REAL,
        flags TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_provenance_source ON provenance(source);
      CREATE INDEX IF NOT EXISTS idx_provenance_trust ON provenance(trust_level);
      CREATE INDEX IF NOT EXISTS idx_provenance_session ON provenance(session_id);
      CREATE INDEX IF NOT EXISTS idx_provenance_timestamp ON provenance(timestamp);
    `);
  }

  /**
   * Create a new provenance record
   */
  create(options: {
    source: string;
    trustLevel: TrustLevel;
    sessionId?: string;
    triggerContext?: string;
    detectionScore?: number;
    flags?: string[];
  }): MemoryProvenance {
    const id = uuidv4();
    const timestamp = new Date();

    const stmt = this.db.prepare(`
      INSERT INTO provenance (
        id, source, trust_level, timestamp, session_id,
        trigger_context, detection_score, flags
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      options.source,
      options.trustLevel,
      timestamp.toISOString(),
      options.sessionId ?? null,
      options.triggerContext ?? null,
      options.detectionScore ?? null,
      options.flags ? JSON.stringify(options.flags) : null
    );

    return {
      id,
      source: options.source,
      trustLevel: options.trustLevel,
      timestamp,
      sessionId: options.sessionId,
      triggerContext: options.triggerContext,
      detectionScore: options.detectionScore,
      flags: options.flags,
    };
  }

  /**
   * Get provenance by ID
   */
  get(id: string): MemoryProvenance | null {
    const stmt = this.db.prepare('SELECT * FROM provenance WHERE id = ?');
    const row = stmt.get(id) as ProvenanceRow | undefined;
    return row ? this.rowToProvenance(row) : null;
  }

  /**
   * List provenance records with filters
   */
  list(options?: {
    source?: string;
    trustLevel?: TrustLevel;
    sessionId?: string;
    limit?: number;
    offset?: number;
  }): MemoryProvenance[] {
    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (options?.source) {
      conditions.push('source = ?');
      params.push(options.source);
    }
    if (options?.trustLevel) {
      conditions.push('trust_level = ?');
      params.push(options.trustLevel);
    }
    if (options?.sessionId) {
      conditions.push('session_id = ?');
      params.push(options.sessionId);
    }

    let query = 'SELECT * FROM provenance';
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    query += ' ORDER BY timestamp DESC';

    if (options?.limit) {
      query += ' LIMIT ?';
      params.push(options.limit);
    }
    if (options?.offset) {
      query += ' OFFSET ?';
      params.push(options.offset);
    }

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as ProvenanceRow[];
    return rows.map((row) => this.rowToProvenance(row));
  }

  /**
   * Get counts by trust level
   */
  getCountsByTrust(): Record<TrustLevel, number> {
    const stmt = this.db.prepare(`
      SELECT trust_level, COUNT(*) as count FROM provenance GROUP BY trust_level
    `);
    const rows = stmt.all() as { trust_level: string; count: number }[];

    const counts: Record<TrustLevel, number> = {
      [TrustLevel.USER]: 0,
      [TrustLevel.TOOL_VERIFIED]: 0,
      [TrustLevel.TOOL_UNVERIFIED]: 0,
      [TrustLevel.AGENT]: 0,
      [TrustLevel.EXTERNAL]: 0,
    };

    for (const row of rows) {
      counts[row.trust_level as TrustLevel] = row.count;
    }

    return counts;
  }

  /**
   * Get counts by source
   */
  getCountsBySource(): Map<string, number> {
    const stmt = this.db.prepare(`
      SELECT source, COUNT(*) as count FROM provenance GROUP BY source
    `);
    const rows = stmt.all() as { source: string; count: number }[];

    const counts = new Map<string, number>();
    for (const row of rows) {
      counts.set(row.source, row.count);
    }
    return counts;
  }

  /**
   * Get flagged entries (detection_score > 0)
   */
  getFlagged(limit?: number): MemoryProvenance[] {
    let query = `
      SELECT * FROM provenance
      WHERE detection_score > 0
      ORDER BY detection_score DESC, timestamp DESC
    `;
    const params: number[] = [];

    if (limit) {
      query += ' LIMIT ?';
      params.push(limit);
    }

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as ProvenanceRow[];
    return rows.map((row) => this.rowToProvenance(row));
  }

  /**
   * Get total count
   */
  getTotal(): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM provenance');
    const row = stmt.get() as { count: number };
    return row.count;
  }

  /**
   * Update provenance record
   */
  update(id: string, updates: Partial<{
    detectionScore: number;
    flags: string[];
  }>): boolean {
    const sets: string[] = [];
    const params: (string | number | null)[] = [];

    if (updates.detectionScore !== undefined) {
      sets.push('detection_score = ?');
      params.push(updates.detectionScore);
    }
    if (updates.flags !== undefined) {
      sets.push('flags = ?');
      params.push(JSON.stringify(updates.flags));
    }

    if (sets.length === 0) return false;

    params.push(id);
    const stmt = this.db.prepare(`UPDATE provenance SET ${sets.join(', ')} WHERE id = ?`);
    const result = stmt.run(...params);
    return result.changes > 0;
  }

  /**
   * Delete provenance record
   */
  delete(id: string): boolean {
    const stmt = this.db.prepare('DELETE FROM provenance WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  /**
   * Convert database row to MemoryProvenance
   */
  private rowToProvenance(row: ProvenanceRow): MemoryProvenance {
    return {
      id: row.id,
      source: row.source,
      trustLevel: row.trust_level as TrustLevel,
      timestamp: new Date(row.timestamp),
      sessionId: row.session_id ?? undefined,
      triggerContext: row.trigger_context ?? undefined,
      detectionScore: row.detection_score ?? undefined,
      flags: row.flags ? JSON.parse(row.flags) : undefined,
    };
  }

  /**
   * Close database connection
   */
  close(): void {
    this.db.close();
  }
}

/**
 * Database row type
 */
interface ProvenanceRow {
  id: string;
  source: string;
  trust_level: string;
  timestamp: string;
  session_id: string | null;
  trigger_context: string | null;
  detection_score: number | null;
  flags: string | null;
}
