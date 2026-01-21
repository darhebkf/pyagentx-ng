import { Geist } from "next/font/google";
import { Head } from "nextra/components";
import "nextra-theme-docs/style.css";
import "./globals.css";
import type { ReactNode } from "react";

const geist = Geist({
  subsets: ["latin"],
  variable: "--font-geist",
});

export const metadata = {
  title: "snmpkit",
  description: "High-performance SNMP toolkit with Rust core",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html
      lang="en"
      dir="ltr"
      suppressHydrationWarning
      className={geist.variable}
    >
      <Head />
      <body className="font-sans">{children}</body>
    </html>
  );
}
