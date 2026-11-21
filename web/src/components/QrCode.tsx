// A pairing code as a QR code: an SVG drawn from the matrix src/qr/encode.ts makes. Always
// dark on white, in either theme, with the quiet zone scanners need.
import { useMemo } from "denext";
import { encodeQr, qrPath } from "../qr/encode.ts";

export function QrCode({ text, label, testId }: { text: string; label: string; testId: string }) {
  const path = useMemo(() => {
    try {
      return qrPath(encodeQr(new TextEncoder().encode(text)));
    } catch {
      return null;
    }
  }, [text]);
  if (!path) return null;
  return (
    <svg
      className="qr"
      viewBox={path.viewBox}
      role="img"
      aria-label={label}
      shape-rendering="crispEdges"
      data-testid={testId}
    >
      <rect className="qr__ground" width="100%" height="100%" />
      <path className="qr__modules" d={path.d} />
    </svg>
  );
}
