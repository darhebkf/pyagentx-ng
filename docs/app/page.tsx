"use client";

import createGlobe from "cobe";
import { motion } from "motion/react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";

function Globe() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (!canvasRef.current) return;

    let phi = 0;
    let width = 0;

    const onResize = () => {
      if (canvasRef.current) {
        width = canvasRef.current.offsetWidth;
      }
    };
    window.addEventListener("resize", onResize);
    onResize();

    const globe = createGlobe(canvasRef.current, {
      devicePixelRatio: 2,
      width: width * 2,
      height: width * 2,
      phi: 0,
      theta: 0.3,
      dark: 1,
      diffuse: 3,
      mapSamples: 16000,
      mapBrightness: 1.2,
      baseColor: [0.035, 0.569, 0.776],
      markerColor: [0.035, 0.569, 0.776],
      glowColor: [0.035, 0.569, 0.776],
      markers: [],
      onRender: (state) => {
        state.phi = phi;
        phi += 0.003;
        state.width = width * 2;
        state.height = width * 2;
      },
    });

    setTimeout(() => {
      if (canvasRef.current) {
        canvasRef.current.style.opacity = "1";
      }
    }, 100);

    return () => {
      globe.destroy();
      window.removeEventListener("resize", onResize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="w-full h-full opacity-0 transition-opacity duration-1000"
      style={{ contain: "layout paint size" }}
    />
  );
}

function Logo() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="240"
      height="52"
      viewBox="0 0 280 60"
      role="img"
      aria-label="snmpkit logo"
    >
      <g
        transform="translate(10, 6)"
        stroke="#c0c0c0"
        fill="none"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M42 16a4 4 0 0 0-2-3.46l-14-8a4 4 0 0 0-4 0l-14 8A4 4 0 0 0 6 16v16a4 4 0 0 0 2 3.46l14 8a4 4 0 0 0 4 0l14-8A4 4 0 0 0 42 32Z" />
        <path d="m6.6 14 17.4 10 17.4-10" />
        <path d="M24 44V24" />
      </g>
      <text
        x="70"
        y="42"
        fontFamily="'Times New Roman', Times, Georgia, serif"
        fontSize="36"
        fontWeight="bold"
        letterSpacing="0.15em"
        fill="#c0c0c0"
      >
        SNMPKIT
      </text>
    </svg>
  );
}

function CTA({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      className="group relative px-4 py-2 text-cyan-600 hover:text-cyan-500 transition-colors"
    >
      <span className="absolute inset-0 border-2 border-cyan-600 rounded sm:hidden" />
      <span className="relative">{children}</span>
      <span className="absolute left-4 right-4 bottom-2 h-px bg-cyan-600 group-hover:scale-x-0 transition-transform duration-300 origin-left hidden sm:block" />
    </Link>
  );
}

function InstallCommand() {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText("uv add snmpkit");
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="group flex items-center gap-3 bg-white/5 border border-white/10 rounded-lg px-4 py-2.5 hover:bg-white/10 hover:border-white/20 transition-all cursor-pointer"
    >
      <span className="text-white/50 text-sm">$</span>
      <code className="text-cyan-400 font-mono text-sm">uv add snmpkit</code>
      <svg
        className="w-4 h-4 ml-2 text-white/30 group-hover:text-white/50 transition-colors"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
        aria-label={copied ? "Copied" : "Copy to clipboard"}
        role="img"
      >
        {copied ? (
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M5 13l4 4L19 7"
          />
        ) : (
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
          />
        )}
      </svg>
    </button>
  );
}

export default function LandingPage() {
  const [showPanels, setShowPanels] = useState(false);
  const [showContent, setShowContent] = useState(false);

  useEffect(() => {
    const panelTimer = setTimeout(() => setShowPanels(true), 1500);
    const contentTimer = setTimeout(() => setShowContent(true), 2400);
    return () => {
      clearTimeout(panelTimer);
      clearTimeout(contentTimer);
    };
  }, []);

  return (
    <div className="min-h-screen w-screen overflow-x-hidden overflow-y-auto relative bg-black">
      {/* Globe — centered background */}
      <div className="absolute inset-0 flex items-center justify-center z-0 overflow-hidden">
        <div className="w-[min(600px,90vw)] h-[min(600px,90vw)] lg:w-[700px] lg:h-[700px]">
          <Globe />
        </div>
      </div>

      {/* Vignette overlay */}
      <div
        className="absolute inset-0 pointer-events-none z-10"
        style={{
          background:
            "radial-gradient(ellipse at center, transparent 0%, rgba(0,0,0,0.25) 40%, rgba(0,0,0,0.6) 65%, black 100%)",
        }}
      />

      {/* Main content */}
      <div className="relative min-h-screen flex items-center justify-center z-20 px-4 lg:px-12 py-12">
        {/* Two halves — slide apart from center */}
        <div className="flex flex-col lg:flex-row items-stretch justify-center w-full max-w-sm sm:max-w-md lg:max-w-none lg:w-auto">
          {/* Left — Code snippet (slides from center → left) */}
          <motion.div
            className="bg-black/40 backdrop-blur-md lg:w-[460px] shrink-0 border border-white/10 rounded-xl lg:rounded-r-none lg:border-r-0 overflow-hidden shadow-2xl order-2 lg:order-1"
            initial={{ opacity: 0, x: 120 }}
            animate={showPanels ? { opacity: 1, x: 0 } : {}}
            transition={{ duration: 0.8, ease: [0.25, 0.1, 0.25, 1] }}
          >
            {/* Window controls */}
            <div className="flex items-center gap-2 px-4 py-3 bg-white/5 border-b border-white/10">
              <div className="w-3 h-3 rounded-full bg-red-500/80" />
              <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
              <div className="w-3 h-3 rounded-full bg-green-500/80" />
              <span className="ml-3 text-white/40 text-xs font-mono">
                example.py
              </span>
            </div>

            {/* Code content */}
            <pre className="p-4 lg:p-5 text-xs sm:text-sm font-mono leading-relaxed overflow-x-auto">
              <code>
                <span className="text-white/40">
                  # Manager: Query SNMP devices
                </span>
                {"\n"}
                <span className="text-purple-400">from</span>
                <span className="text-white/90"> snmpkit.manager </span>
                <span className="text-purple-400">import</span>
                <span className="text-white/90"> Manager</span>
                {"\n\n"}
                <span className="text-purple-400">async with</span>
                <span className="text-cyan-400"> Manager</span>
                <span className="text-white/90">(</span>
                <span className="text-green-400">"192.168.1.1"</span>
                <span className="text-white/90">) </span>
                <span className="text-purple-400">as</span>
                <span className="text-white/90"> mgr:</span>
                {"\n"}
                <span className="text-white/90"> value = </span>
                <span className="text-purple-400">await</span>
                <span className="text-white/90"> mgr.</span>
                <span className="text-cyan-400">get</span>
                <span className="text-white/90">(</span>
                <span className="text-green-400">"1.3.6.1.2.1.1.1.0"</span>
                <span className="text-white/90">)</span>
                {"\n"}
                <span className="text-white/90"> </span>
                <span className="text-purple-400">async for</span>
                <span className="text-white/90"> oid, val </span>
                <span className="text-purple-400">in</span>
                <span className="text-white/90"> mgr.</span>
                <span className="text-cyan-400">walk</span>
                <span className="text-white/90">(</span>
                <span className="text-green-400">"1.3.6.1.2.1.2"</span>
                <span className="text-white/90">):</span>
                {"\n"}
                <span className="text-white/90"> </span>
                <span className="text-cyan-400">print</span>
                <span className="text-white/90">(</span>
                <span className="text-green-400">f"</span>
                <span className="text-orange-400">{"{oid}"}</span>
                <span className="text-green-400"> = </span>
                <span className="text-orange-400">{"{val}"}</span>
                <span className="text-green-400">"</span>
                <span className="text-white/90">)</span>
                {"\n\n"}
                <span className="text-white/40">
                  # Agent: Expose custom OIDs via AgentX
                </span>
                {"\n"}
                <span className="text-purple-400">from</span>
                <span className="text-white/90"> snmpkit.agent </span>
                <span className="text-purple-400">import</span>
                <span className="text-white/90"> Agent, Updater</span>
                {"\n\n"}
                <span className="text-purple-400">class</span>
                <span className="text-cyan-400"> MyUpdater</span>
                <span className="text-white/90">(Updater):</span>
                {"\n"}
                <span className="text-white/90"> </span>
                <span className="text-purple-400">async def</span>
                <span className="text-cyan-400"> update</span>
                <span className="text-white/90">(self):</span>
                {"\n"}
                <span className="text-white/90"> self.</span>
                <span className="text-cyan-400">set_INTEGER</span>
                <span className="text-white/90">(</span>
                <span className="text-green-400">"1.0"</span>
                <span className="text-white/90">, </span>
                <span className="text-orange-400">42</span>
                <span className="text-white/90">)</span>
                {"\n\n"}
                <span className="text-white/90">agent = </span>
                <span className="text-cyan-400">Agent</span>
                <span className="text-white/90">()</span>
                {"\n"}
                <span className="text-white/90">agent.</span>
                <span className="text-cyan-400">register</span>
                <span className="text-white/90">(</span>
                <span className="text-green-400">"1.3.6.1.4.1.12345"</span>
                <span className="text-white/90">, MyUpdater())</span>
                {"\n"}
                <span className="text-white/90">agent.</span>
                <span className="text-cyan-400">start_sync</span>
                <span className="text-white/90">()</span>
              </code>
            </pre>
          </motion.div>

          {/* Right — Transparent extension (slides from center → right) */}
          <motion.div
            className="relative lg:w-[360px] shrink-0 border border-white/10 rounded-xl lg:rounded-l-none lg:border-l-0 bg-white/5 backdrop-blur-sm p-6 lg:p-8 flex flex-col justify-center space-y-5 order-1 lg:order-2"
            initial={{ opacity: 0, x: -120 }}
            animate={showPanels ? { opacity: 1, x: 0 } : {}}
            transition={{ duration: 0.8, ease: [0.25, 0.1, 0.25, 1] }}
          >
            {/* Divider line between panels (drawn by lg:border-l on parent won't work since we removed it — use an inner left border) */}
            <div className="absolute inset-y-0 left-0 w-px bg-white/10 hidden lg:block" />

            <div className="space-y-5">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={showContent ? { opacity: 1, y: 0 } : {}}
                transition={{ duration: 0.4 }}
              >
                <Logo />
              </motion.div>

              <motion.p
                className="text-white/70 text-sm lg:text-base"
                initial={{ opacity: 0, y: 20 }}
                animate={showContent ? { opacity: 1, y: 0 } : {}}
                transition={{ duration: 0.4, delay: 0.1 }}
              >
                High-performance SNMP toolkit for Python, powered by Rust.
                <br />
                <span className="text-white/50">
                  127x faster encoding. Full SNMPv1/v2c/v3 support.
                </span>
              </motion.p>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={showContent ? { opacity: 1, y: 0 } : {}}
                transition={{ duration: 0.4, delay: 0.2 }}
              >
                <InstallCommand />
              </motion.div>

              <motion.div
                className="flex gap-6 pt-1"
                initial={{ opacity: 0, y: 20 }}
                animate={showContent ? { opacity: 1, y: 0 } : {}}
                transition={{ duration: 0.4, delay: 0.3 }}
              >
                <CTA href="/docs/introduction">Get Started</CTA>
                <CTA href="/docs/examples">Examples</CTA>
              </motion.div>
            </div>
          </motion.div>
        </div>
      </div>

      {/* Copyright */}
      <motion.div
        className="absolute bottom-4 left-0 right-0 text-center text-xs text-white/30 z-20"
        initial={{ opacity: 0 }}
        animate={showContent ? { opacity: 1 } : {}}
        transition={{ duration: 0.6, delay: 0.2 }}
      >
        © 2026 SnmpKit. All rights reserved.
      </motion.div>
    </div>
  );
}
