// Codes are set in Atkinson Hyperlegible Mono and always run left to right.

/** Splits a string into groups of `size` characters. */
export function groups(value: string, size: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < value.length; i += size) out.push(value.slice(i, i + size));
  return out;
}

/** A pairing code, grouped in fours. */
export function CodeBlock(
  { code, label, testId, small = false }: {
    code: string;
    label: string;
    testId: string;
    /** A long code (a pairing code is a few hundred characters): set smaller. */
    small?: boolean;
  },
) {
  const clean = code.replace(/\s+/g, "");
  return (
    <code
      className={small ? "code code--small" : "code"}
      role="group"
      aria-label={label}
      data-testid={testId}
    >
      {groups(clean, 4).map((group, i) => <span key={i}>{group}</span>)}
    </code>
  );
}

/** A safety number: 60 digits as 12 groups of 5. */
export function SafetyNumber(
  { digits, label, testId }: { digits: string; label: string; testId: string },
) {
  const clean = digits.replace(/\D+/g, "");
  return (
    <div className="safety-number" role="group" aria-label={label} data-testid={testId}>
      {groups(clean, 5).map((group, i) => <span key={i}>{group}</span>)}
    </div>
  );
}
