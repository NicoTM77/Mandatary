import { createContext, useContext } from 'react';

/**
 * Programmatic focus on appearance (error summaries, reveal-once panels) is part of the interaction
 * contract. The synthetic gallery renders dozens of such states at once, so it turns this off to
 * stop the page jumping; real screens never do.
 */
export const AutoFocusContext = createContext(true);

export function useAutoFocus(): boolean {
  return useContext(AutoFocusContext);
}
