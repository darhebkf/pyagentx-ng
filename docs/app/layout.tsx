import { Head } from "nextra/components";
import { getPageMap } from "nextra/page-map";
import { Footer, Layout, Navbar } from "nextra-theme-docs";
import "nextra-theme-docs/style.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "snmpkit",
  description: "High-performance SNMP toolkit with Rust core",
};

const navbar = (
  <Navbar
    logo={<b>snmpkit</b>}
    projectLink="https://github.com/achmedius/snmpkit"
  />
);

const footer = <Footer>AGPL-3.0 {new Date().getFullYear()} © snmpkit</Footer>;

export default async function RootLayout({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <Head />
      <body>
        <Layout
          navbar={navbar}
          pageMap={await getPageMap()}
          docsRepositoryBase="https://github.com/achmedius/snmpkit/tree/main/docs"
          footer={footer}
        >
          {children}
        </Layout>
      </body>
    </html>
  );
}
