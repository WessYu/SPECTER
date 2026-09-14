export interface CodeToken {
  readonly value: string;
  readonly line: number;
  readonly column: number;
}

function isIdentifierStart(char: string): boolean {
  return /[A-Za-z_$]/.test(char);
}

function isIdentifierPart(char: string): boolean {
  return /[A-Za-z0-9_$]/.test(char);
}

export function tokenizeCode(source: string): readonly CodeToken[] {
  const tokens: CodeToken[] = [];
  let index = 0;
  let line = 1;
  let column = 1;

  const advance = (): string => {
    const char = source[index] ?? "";
    index += 1;
    if (char === "\n") {
      line += 1;
      column = 1;
    } else column += 1;
    return char;
  };

  while (index < source.length) {
    const char = source[index] ?? "";
    if (/\s/.test(char)) {
      advance();
      continue;
    }

    if (char === "/" && source[index + 1] === "/") {
      while (index < source.length && advance() !== "\n") undefined;
      continue;
    }
    if (char === "/" && source[index + 1] === "*") {
      advance();
      advance();
      while (index < source.length) {
        const current = advance();
        if (current === "*" && source[index] === "/") {
          advance();
          break;
        }
      }
      continue;
    }

    if (char === '"' || char === "'" || char === "`") {
      const quote = advance();
      let escaped = false;
      while (index < source.length) {
        const current = advance();
        if (escaped) {
          escaped = false;
          continue;
        }
        if (current === "\\") {
          escaped = true;
          continue;
        }
        if (current === quote) break;
      }
      continue;
    }

    if (isIdentifierStart(char)) {
      const startLine = line;
      const startColumn = column;
      let value = advance();
      while (index < source.length && isIdentifierPart(source[index] ?? "")) value += advance();
      tokens.push({ value, line: startLine, column: startColumn });
      continue;
    }

    tokens.push({ value: advance(), line, column: Math.max(1, column - 1) });
  }

  return tokens;
}

export function findIdentifierCall(
  tokens: readonly CodeToken[],
  identifier: string,
): readonly CodeToken[] {
  const matches: CodeToken[] = [];
  for (let index = 0; index < tokens.length - 1; index += 1) {
    const token = tokens[index];
    const next = tokens[index + 1];
    const previous = index > 0 ? tokens[index - 1] : undefined;
    if (token?.value === identifier && next?.value === "(" && previous?.value !== ".")
      matches.push(token);
  }
  return matches;
}
