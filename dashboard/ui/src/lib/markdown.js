// The narrative's markdown subset, as data. Kept out of the component so it
// can be tested without a DOM: the first version lived inline and missed the
// shape the model actually writes.
//
// Subset: #/##/### headings, -/* and N. lists, **bold**, and `code`.
import { looksLikeHash, looksLikeIndicator } from "./format.js";

function codeToken(v) {
  if (looksLikeHash(v)) return { t: "hash", v };
  if (looksLikeIndicator(v)) return { t: "indicator", v };
  return { t: "code", v };
}

// Inline tokens. Code inside bold is the case that matters: the narrative
// routinely writes **Cert rotation on `host`**, and treating the whole bold
// span as one plain token showed the backticks literally.
export function inline(line) {
  const out = [];
  for (const part of String(line).split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean)) {
    const bold = part.match(/^\*\*([^*]+)\*\*$/);
    if (bold) {
      for (const piece of bold[1].split(/(`[^`]+`)/g).filter(Boolean)) {
        const code = piece.match(/^`([^`]+)`$/);
        out.push(code ? codeToken(code[1]) : { t: "text", v: piece, strong: true });
      }
      continue;
    }
    const code = part.match(/^`([^`]+)`$/);
    out.push(code ? codeToken(code[1]) : { t: "text", v: part });
  }
  return out;
}

export function parse(src) {
  const blocks = [];
  let list = null;
  for (const raw of String(src).split("\n")) {
    const line = raw.trimEnd();
    if (!line.trim()) { list = null; continue; }
    const heading = line.match(/^#{1,3}\s+(.*)$/);
    if (heading) { list = null; blocks.push({ type: "heading", text: heading[1] }); continue; }
    const bullet = line.match(/^\s*[-*]\s+(.*)$/);
    const numbered = line.match(/^\s*\d+\.\s+(.*)$/);
    if (bullet || numbered) {
      const ordered = !!numbered;
      if (!list || list.ordered !== ordered) {
        list = { type: "list", ordered, items: [] };
        blocks.push(list);
      }
      list.items.push(inline((bullet || numbered)[1]));
      continue;
    }
    list = null;
    blocks.push({ type: "p", parts: inline(line) });
  }
  return blocks;
}
