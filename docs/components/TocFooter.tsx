"use client";

import { usePathname } from "next/navigation";
import { TocActions } from "./TocActions";

const REPO_BASE = "https://github.com/darhebkf/snmpkit/tree/main/docs";
const FEEDBACK_URL = "https://github.com/darhebkf/snmpkit/issues/new?labels=feedback";

export function TocFooter() {
  const pathname = usePathname();
  const editUrl = `${REPO_BASE}/app${pathname}/page.mdx`;

  return <TocActions editUrl={editUrl} feedbackUrl={FEEDBACK_URL} />;
}
