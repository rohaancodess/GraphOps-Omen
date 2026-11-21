export const MAX_BLAST_HOPS = 30;

/** Colour bands for hop depths beyond 3. */
export function hopColor(hop: number): string {
  switch (hop) {
    case 1: return '#F97316';   // orange
    case 2: return '#FBBF24';   // amber/yellow
    case 3: return '#38BDF8';   // sky blue
    case 4:
    case 5: return '#818CF8';   // indigo
    default: return '#94A3B8';  // slate (6+)
  }
}

export function hopBorderColor(hop: number): string {
  switch (hop) {
    case 1: return '#FDBA74';
    case 2: return '#FEF08A';
    case 3: return '#BAE6FD';
    case 4:
    case 5: return '#A5B4FC';
    default: return '#CBD5E1';
  }
}