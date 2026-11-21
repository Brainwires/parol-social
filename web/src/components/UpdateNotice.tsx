// "A new version is ready": the one notice that is neither amber nor red. Shown wherever the
// person is (the list, and the screens before the app), until they reload.
import { t } from "../i18n/index.ts";
import { applyUpdate, updateReady } from "../platform/service-worker.ts";
import { Panel } from "./Panel.tsx";

export function UpdateNotice() {
  if (!updateReady.value) return null;
  return (
    <Panel
      tone="plain"
      testId="update-ready"
      title={t("update.title")}
      actions={[{
        label: t("update.reload"),
        testId: "update-reload",
        primary: true,
        onClick: applyUpdate,
      }]}
    >
      {t("update.body")}
    </Panel>
  );
}
