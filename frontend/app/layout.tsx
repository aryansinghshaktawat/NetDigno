import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NetDigno — Network Diagnostics & Security Platform",
  description:
    "Network infrastructure diagnostics and security assessment platform. DNS resolution, TCP connectivity checks, Nmap port scanning, scan history, and change detection.",
  keywords: ["network diagnostics", "port scanner", "nmap", "security assessment", "DNS lookup"],
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
