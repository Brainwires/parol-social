import { createContext, useContext } from "denext";
import type { AppStore } from "./store.ts";

const StoreContext = createContext<AppStore | null>(null);

export const StoreProvider = StoreContext.Provider;

export function useStore(): AppStore {
  const store = useContext(StoreContext);
  if (!store) throw new Error("no AppStore: wrap the tree in <StoreProvider>");
  return store;
}
