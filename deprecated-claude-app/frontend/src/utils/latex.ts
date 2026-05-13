import katex from 'katex';

/**
 * Render LaTeX in content.
 *
 * Supports four math delimiters:
 *   - Display: $$...$$  and  \[...\]
 *   - Inline:  $...$    and  \(...\)
 *
 * IMPORTANT ORDERING: LaTeX must be extracted from the source text BEFORE
 * markdown parses it, because CommonMark backslash-escapes (`\(`, `\)`, `\[`,
 * `\]`) get consumed by marked.parse() — turning `\(n \ge 1\)` into `(n \ge 1)`
 * before KaTeX can ever see it.
 *
 * Pipeline:
 *   1. extractMath(content) → replaces math regions with placeholder tokens
 *      and returns the substituted text plus a map of rendered HTML.
 *   2. marked.parse() runs on the substituted text. Placeholders survive
 *      because they're plain alphanumerics.
 *   3. restoreMath(html, map) substitutes the rendered HTML back in.
 *
 * Currency-safety: the `$...$` inline matcher is intentionally strict —
 * it requires a non-digit, non-whitespace character immediately inside both
 * delimiters and refuses to match if a digit follows the closing `$`. So
 * `$100. Strike at $110, premium $3` stays as text. Math intended as inline
 * math should use `\(...\)` (which is what Claude and GPT typically emit
 * anyway) or display form `$$...$$`.
 */

interface KatexOptions {
  throwOnError: boolean;
  strict: boolean;
  output: 'html';
  displayMode: boolean;
}

const BASE_OPTIONS: Omit<KatexOptions, 'displayMode'> = {
  throwOnError: false,
  strict: false, // Suppress warnings about unicode box-drawing chars etc.
  output: 'html',
};

// Placeholder tokens use a private-use unicode prefix so they can't appear
// in user content, then plain ASCII so markdown won't transform them.
const PLACEHOLDER_PREFIX = 'ARCMATH';
const PLACEHOLDER_SUFFIX = '';
const PLACEHOLDER_RE = new RegExp(
  `${PLACEHOLDER_PREFIX}(\\d+)${PLACEHOLDER_SUFFIX}`,
  'g',
);

function renderToHtml(latex: string, displayMode: boolean, original: string): string {
  try {
    return katex.renderToString(latex.trim(), { ...BASE_OPTIONS, displayMode });
  } catch (err) {
    console.warn(`[latex] render error (${displayMode ? 'display' : 'inline'}):`, err);
    // Fall back to the unrendered original so the user sees their source.
    return original;
  }
}

/**
 * Strict inline `$...$` matcher.
 *
 * Rules (any one failure means the candidate is treated as plain text):
 *   - Opening `$` must be followed by a non-digit, non-whitespace character.
 *   - Closing `$` must be preceded by a non-whitespace character.
 *   - Closing `$` must not be followed by a digit.
 *   - No newlines inside the match (would suggest paragraph break, not math).
 *   - Not part of `$$` (handled separately as display math).
 *
 * Examples:
 *   ✓  `$x + 1$`           — letter follows opening, no digit issues
 *   ✓  `$\\frac{1}{2}$`    — backslash follows opening
 *   ✗  `$100`              — digit follows opening
 *   ✗  `strike $110, $3`   — digit follows opening
 *   ✗  `cost is $ 50 $`    — whitespace follows opening
 */
const INLINE_DOLLAR_RE =
  /(?<!\$)\$(?!\$)([^\s\d$][^\n$]*?[^\s$])\$(?!\d)/g;

/**
 * Extract math regions from raw model output, replacing them with placeholder
 * tokens. Order matters: longest/most-specific delimiters first so we don't
 * partially consume display math.
 */
export function extractMath(content: string): { text: string; rendered: string[] } {
  const rendered: string[] = [];
  let text = content;

  const replace = (re: RegExp, displayMode: boolean) => {
    text = text.replace(re, (match, body) => {
      const html = renderToHtml(body, displayMode, match);
      const idx = rendered.length;
      rendered.push(html);
      return `${PLACEHOLDER_PREFIX}${idx}${PLACEHOLDER_SUFFIX}`;
    });
  };

  // Order: $$ first (greediest), then \[ \], then strict $, then \( \).
  // Display math: $$ ... $$
  replace(/\$\$([\s\S]+?)\$\$/g, true);
  // Display math: \[ ... \]
  replace(/\\\[([\s\S]+?)\\\]/g, true);
  // Inline math: \( ... \)   — must run BEFORE $...$ so that escapes inside
  // \(...\) aren't grabbed by the dollar matcher.
  replace(/\\\(([\s\S]+?)\\\)/g, false);
  // Inline math: $ ... $   (currency-safe; see INLINE_DOLLAR_RE comment)
  replace(INLINE_DOLLAR_RE, false);

  return { text, rendered };
}

/**
 * Substitute the rendered KaTeX HTML back in for placeholder tokens.
 * Safe to call on either raw text or post-markdown HTML.
 */
export function restoreMath(html: string, rendered: string[]): string {
  return html.replace(PLACEHOLDER_RE, (_, idx) => rendered[Number(idx)] ?? '');
}

/**
 * Legacy single-pass API.
 *
 * Kept for backwards compatibility (in case any caller still depends on the
 * old "render math in-place over an HTML string" behavior), but DO NOT use
 * for new code: it runs after markdown has already stripped `\(`/`\[`
 * delimiters. Use `extractMath` + `restoreMath` around `marked.parse` instead.
 *
 * @deprecated Use `extractMath` / `restoreMath` around markdown parsing.
 */
export function renderLatex(content: string): string {
  if (!content.includes('$') && !content.includes('\\(') && !content.includes('\\[')) {
    return content;
  }
  const { text, rendered } = extractMath(content);
  return restoreMath(text, rendered);
}

/**
 * KaTeX-generated tags that need to be allowed through DOMPurify so the
 * rendered math survives sanitization.
 */
export const KATEX_ALLOWED_TAGS = [
  'span', 'math', 'semantics', 'mrow', 'mi', 'mo', 'mn', 'msup', 'msub',
  'mfrac', 'mover', 'munder', 'munderover', 'msqrt', 'mroot', 'mtable',
  'mtr', 'mtd', 'mtext', 'mspace', 'annotation', 'svg', 'line', 'path',
];

/** Attributes KaTeX emits. */
export const KATEX_ALLOWED_ATTRS = [
  'class', 'style', 'aria-hidden', 'encoding', 'xmlns', 'xlink:href',
  'viewBox', 'width', 'height', 'fill', 'stroke', 'stroke-width',
  'd', 'x', 'y', 'x1', 'x2', 'y1', 'y2',
];
