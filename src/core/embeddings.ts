import OpenAI from 'openai';

/**
 * Embedding client for Layer 2 semantic analysis
 * Uses OpenAI's text-embedding-3-small model
 */
export class EmbeddingClient {
  private client: OpenAI;
  private cache: Map<string, number[]>;
  private model: string;

  constructor(apiKey: string, model = 'text-embedding-3-small') {
    this.client = new OpenAI({ apiKey });
    this.cache = new Map();
    this.model = model;
  }

  /**
   * Get embedding for a single text
   * Uses cache to avoid redundant API calls
   */
  async getEmbedding(text: string): Promise<number[]> {
    const cached = this.cache.get(text);
    if (cached) {
      return cached;
    }

    const response = await this.client.embeddings.create({
      model: this.model,
      input: text,
    });

    const embedding = response.data[0].embedding;
    this.cache.set(text, embedding);
    return embedding;
  }

  /**
   * Get embeddings for multiple texts in a batch
   */
  async getEmbeddings(texts: string[]): Promise<Map<string, number[]>> {
    const results = new Map<string, number[]>();
    const uncached: string[] = [];

    // Check cache first
    for (const text of texts) {
      const cached = this.cache.get(text);
      if (cached) {
        results.set(text, cached);
      } else {
        uncached.push(text);
      }
    }

    // Batch request for uncached texts
    if (uncached.length > 0) {
      const response = await this.client.embeddings.create({
        model: this.model,
        input: uncached,
      });

      for (let i = 0; i < uncached.length; i++) {
        const text = uncached[i];
        const embedding = response.data[i].embedding;
        this.cache.set(text, embedding);
        results.set(text, embedding);
      }
    }

    return results;
  }

  /**
   * Preload embeddings into cache (useful for exemplars)
   */
  async preloadEmbeddings(texts: string[]): Promise<void> {
    await this.getEmbeddings(texts);
  }

  /**
   * Clear the embedding cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get cache size
   */
  getCacheSize(): number {
    return this.cache.size;
  }
}

/**
 * Calculate cosine similarity between two vectors
 */
export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) {
    throw new Error('Vectors must have the same length');
  }

  let dotProduct = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }

  normA = Math.sqrt(normA);
  normB = Math.sqrt(normB);

  if (normA === 0 || normB === 0) {
    return 0;
  }

  return dotProduct / (normA * normB);
}

/**
 * Find the most similar text from a set of candidates
 */
export function findMostSimilar(
  targetEmbedding: number[],
  candidateEmbeddings: Map<string, number[]>
): { text: string; similarity: number } | null {
  let bestMatch: { text: string; similarity: number } | null = null;

  for (const [text, embedding] of candidateEmbeddings) {
    const similarity = cosineSimilarity(targetEmbedding, embedding);
    if (!bestMatch || similarity > bestMatch.similarity) {
      bestMatch = { text, similarity };
    }
  }

  return bestMatch;
}
