// What the store can do with this device's protected storage besides running the engine on
// it: the passphrase lock, the backup file, and a restore. The page's side of
// `DeviceVault` (src/state/engine-store.ts).
import { collectBackup, decodeBackup, encodeBackup, restoredRows } from "../engine/backup.ts";
import type { SealedStorage } from "../engine/sealed-storage.ts";
import type { SettingRow } from "../engine/storage.ts";
import type { Vault, VaultCrypto } from "../engine/vault.ts";
import type { DeviceVault } from "../state/engine-store.ts";

/** store `settings`, key `backup`: when this device last made a backup. Not in backups. */
const BACKUP_SETTING = "backup";

export function deviceVault(
  vault: Vault,
  storage: SealedStorage,
  crypto: VaultCrypto,
): DeviceVault {
  return {
    hasPassphrase: () => vault.hasPassphrase,
    setPassphrase: (next) => vault.setPassphrase(next),
    changePassphrase: (current, next) => vault.changePassphrase(current, next),
    removePassphrase: (current) => vault.removePassphrase(current),

    async backup(passphrase, options) {
      const now = crypto.now();
      const contents = collectBackup(await storage.snapshot(), {
        history: options.history,
        peerId: options.peerId,
        now,
      });
      const file = await encodeBackup(crypto, passphrase, contents);
      const row: SettingRow = { key: BACKUP_SETTING, value: { lastMs: now } };
      // The file exists whether or not its date could be noted.
      await storage.write([{ op: "put", store: "settings", value: row }]).catch(() => {});
      return { bytes: file, madeMs: now };
    },

    async restore(file, passphrase) {
      // Read and checked in full before anything on this device is touched.
      const contents = await decodeBackup(crypto, passphrase, file);
      await storage.replaceAll(restoredRows(contents, crypto.now()));
    },

    async lastBackupMs() {
      const row = await storage.get<SettingRow>("settings", BACKUP_SETTING);
      const last = (row?.value as { lastMs?: unknown } | undefined)?.lastMs;
      return typeof last === "number" ? last : null;
    },
  };
}
