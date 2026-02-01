import Database from 'better-sqlite3';
import { v4 as uuidv4 } from 'uuid';
import { TrustLevel, QuarantinedMemory, QuarantineStatus } from '../core/types.js';

/**
 * SQLite-based quarantine store for flagged memories
 */
export class QuarantineStore {
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
      CREATE TABLE IF NOT EXISTS quarantine (
        id TEXT PRIMARY KEY,
        text TEXT NOT NULL,
        source TEXT NOT NULL,
        trust_level TEXT NOT NULL,
        layer1_flags TEXT,
        layer2_similarity REAL,
        layer2_exemplar TEXT,
        layer3_verdict TEXT,
        layer3_reasoning TEXT,
        quarantined_at TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        reviewed_at TEXT,
        reviewed_by TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);
      CREATE INDEX IF NOT EXISTS idx_quarantine_date ON quarantine(quarantined_at);
    `);

    // Migration: add Layer 3 columns if they don't exist
    try {
      this.db.exec(`ALTER TABLE quarantine ADD COLUMN layer3_verdict TEXT`);
    } catch { /* Column already exists */ }
    try {
      this.db.exec(`ALTER TABLE quarantine ADD COLUMN layer3_reasoning TEXT`);
    } catch { /* Column already exists */ }
  }

  /**
   * Add a memory to quarantine
   */
  add(options: {
    text: string;
    source: string;
    trustLevel: TrustLevel;
    layer1Flags: string[];
    layer2Similarity: number;
    layer2Exemplar?: string;
    layer3Verdict?: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
    layer3Reasoning?: string;
  }): QuarantinedMemory {
    const id = uuidv4();
    const quarantinedAt = new Date();

    const stmt = this.db.prepare(`
      INSERT INTO quarantine (
        id, text, source, trust_level, layer1_flags, layer2_similarity,
        layer2_exemplar, layer3_verdict, layer3_reasoning, quarantined_at, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    `);

    stmt.run(
      id,
      options.text,
      options.source,
      options.trustLevel,
      JSON.stringify(options.layer1Flags),
      options.layer2Similarity,
      options.layer2Exemplar ?? null,
      options.layer3Verdict ?? null,
      options.layer3Reasoning ?? null,
      quarantinedAt.toISOString()
    );

    return {
      id,
      text: options.text,
      source: options.source,
      trustLevel: options.trustLevel,
      layer1Flags: options.layer1Flags,
      layer2Similarity: options.layer2Similarity,
      layer2Exemplar: options.layer2Exemplar,
      layer3Verdict: options.layer3Verdict,
      layer3Reasoning: options.layer3Reasoning,
      quarantinedAt,
      status: 'pending',
    };
  }

  /**
   * Get a quarantined memory by ID
   */
  get(id: string): QuarantinedMemory | null {
    const stmt = this.db.prepare('SELECT * FROM quarantine WHERE id = ?');
    const row = stmt.get(id) as QuarantineRow | undefined;
    return row ? this.rowToMemory(row) : null;
  }

  /**
   * List quarantined memories with optional status filter
   */
  list(options?: {
    status?: QuarantineStatus;
    limit?: number;
    offset?: number;
  }): QuarantinedMemory[] {
    let query = 'SELECT * FROM quarantine';
    const params: (string | number)[] = [];

    if (options?.status) {
      query += ' WHERE status = ?';
      params.push(options.status);
    }

    query += ' ORDER BY quarantined_at DESC';

    if (options?.limit) {
      query += ' LIMIT ?';
      params.push(options.limit);
    }

    if (options?.offset) {
      query += ' OFFSET ?';
      params.push(options.offset);
    }

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as QuarantineRow[];
    return rows.map((row) => this.rowToMemory(row));
  }

  /**
   * Approve a quarantined memory
   */
  approve(id: string, reviewedBy?: string): boolean {
    return this.updateStatus(id, 'approved', reviewedBy);
  }

  /**
   * Reject a quarantined memory
   */
  reject(id: string, reviewedBy?: string): boolean {
    return this.updateStatus(id, 'rejected', reviewedBy);
  }

  /**
   * Update status of a quarantined memory
   */
  private updateStatus(id: string, status: QuarantineStatus, reviewedBy?: string): boolean {
    const stmt = this.db.prepare(`
      UPDATE quarantine
      SET status = ?, reviewed_at = ?, reviewed_by = ?
      WHERE id = ?
    `);

    const result = stmt.run(status, new Date().toISOString(), reviewedBy ?? null, id);
    return result.changes > 0;
  }

  /**
   * Delete a quarantined memory
   */
  delete(id: string): boolean {
    const stmt = this.db.prepare('DELETE FROM quarantine WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  /**
   * Get counts by status
   */
  getCounts(): Record<QuarantineStatus, number> {
    const stmt = this.db.prepare(`
      SELECT status, COUNT(*) as count FROM quarantine GROUP BY status
    `);
    const rows = stmt.all() as { status: QuarantineStatus; count: number }[];

    const counts: Record<QuarantineStatus, number> = {
      pending: 0,
      approved: 0,
      rejected: 0,
    };

    for (const row of rows) {
      counts[row.status] = row.count;
    }

    return counts;
  }

  /**
   * Get total count
   */
  getTotal(): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM quarantine');
    const row = stmt.get() as { count: number };
    return row.count;
  }

  /**
   * Convert database row to QuarantinedMemory
   */
  private rowToMemory(row: QuarantineRow): QuarantinedMemory {
    return {
      id: row.id,
      text: row.text,
      source: row.source,
      trustLevel: row.trust_level as TrustLevel,
      layer1Flags: JSON.parse(row.layer1_flags || '[]'),
      layer2Similarity: row.layer2_similarity,
      layer2Exemplar: row.layer2_exemplar ?? undefined,
      layer3Verdict: row.layer3_verdict as QuarantinedMemory['layer3Verdict'] ?? undefined,
      layer3Reasoning: row.layer3_reasoning ?? undefined,
      quarantinedAt: new Date(row.quarantined_at),
      status: row.status as QuarantineStatus,
      reviewedAt: row.reviewed_at ? new Date(row.reviewed_at) : undefined,
      reviewedBy: row.reviewed_by ?? undefined,
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
interface QuarantineRow {
  id: string;
  text: string;
  source: string;
  trust_level: string;
  layer1_flags: string;
  layer2_similarity: number;
  layer2_exemplar: string | null;
  layer3_verdict: string | null;
  layer3_reasoning: string | null;
  quarantined_at: string;
  status: string;
  reviewed_at: string | null;
  reviewed_by: string | null;
}
