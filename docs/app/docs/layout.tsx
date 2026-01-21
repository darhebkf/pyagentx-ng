import Image from "next/image";
import { getPageMap } from "nextra/page-map";
import { Layout, Navbar } from "nextra-theme-docs";
import type { ReactNode } from "react";
import { ThemeToggle } from "@/components/ThemeToggle";
import { TocFooter } from "@/components/TocFooter";

const logo = (
  <>
    <Image
      src="/logo-light.svg"
      alt="snmpkit"
      width={120}
      height={28}
      className="dark:hidden"
    />
    <Image
      src="/logo-dark.svg"
      alt="snmpkit"
      width={120}
      height={28}
      className="hidden dark:block"
    />
  </>
);

const navbar = (
  <Navbar logo={logo} projectLink="https://github.com/darhebkf/snmpkit">
    <ThemeToggle />
  </Navbar>
);

const footer = (
  <footer className="py-2 text-center text-sm text-neutral-500 dark:text-neutral-400 border-t border-neutral-200 dark:border-neutral-800 backdrop-blur-md bg-white/70 dark:bg-neutral-900/70">
    © 2026 SnmpKit. All rights reserved.
  </footer>
);

export default async function DocsLayout({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <Layout
      navbar={navbar}
      pageMap={await getPageMap("/docs")}
      docsRepositoryBase="https://github.com/darhebkf/snmpkit/tree/main/docs"
      footer={footer}
      sidebar={{ toggleButton: false }}
      darkMode={false}
      editLink={null}
      feedback={{ content: null }}
      copyPageButton={false}
      toc={{ backToTop: null, extraContent: <TocFooter /> }}
    >
      {children}
    </Layout>
  );
}
