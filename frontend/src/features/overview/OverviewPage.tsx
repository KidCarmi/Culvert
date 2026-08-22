// FE-2 placeholder landing page. NOT the product dashboard (FE-4+) — it
// exists so the shell has a stable index route and points reviewers at the
// design-system gallery.
import type { JSX } from "react";
import { Link } from "react-router";
import { PageHeader } from "../../layouts/AppShell";
import { Callout } from "../../design-system/primitives";

export function OverviewPage(): JSX.Element {
  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="CULVERT frontend platform preview — no product data is wired yet"
      />
      <Callout variant="info" title="Experimental preview surface">
        This is the FE-2 platform foundation: design tokens, application shell,
        and the component system future screens are assembled from. Product
        features continue to live in the current administration UI. Review the{" "}
        <Link to="/design-system">design-system gallery</Link> for the component
        inventory.
      </Callout>
    </>
  );
}
