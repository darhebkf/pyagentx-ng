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

function Logo({ onAnimationComplete }: { onAnimationComplete: () => void }) {
  return (
    <motion.svg
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
        <motion.path
          d="M42 16a4 4 0 0 0-2-3.46l-14-8a4 4 0 0 0-4 0l-14 8A4 4 0 0 0 6 16v16a4 4 0 0 0 2 3.46l14 8a4 4 0 0 0 4 0l14-8A4 4 0 0 0 42 32Z"
          initial={{ pathLength: 0 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 1.5, ease: "easeInOut" }}
        />
        <motion.path
          d="m6.6 14 17.4 10 17.4-10"
          initial={{ pathLength: 0 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 1, ease: "easeInOut", delay: 0.3 }}
        />
        <motion.path
          d="M24 44V24"
          initial={{ pathLength: 0 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 0.8, ease: "easeInOut", delay: 0.5 }}
        />
      </g>
      <motion.text
        x="70"
        y="42"
        fontFamily="'Times New Roman', Times, Georgia, serif"
        fontSize="36"
        fontWeight="bold"
        letterSpacing="0.15em"
        fill="none"
        stroke="#c0c0c0"
        strokeWidth="1"
        initial={{ strokeDasharray: 500, strokeDashoffset: 500 }}
        animate={{ strokeDashoffset: 0, fill: "#c0c0c0" }}
        transition={{
          strokeDashoffset: { duration: 2, ease: "easeInOut", delay: 0.6 },
          fill: { duration: 0.5, delay: 2.4 },
        }}
        onAnimationComplete={onAnimationComplete}
      >
        SNMPKIT
      </motion.text>
    </motion.svg>
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

function CodeSnippet({ show }: { show: boolean }) {
  return (
    <motion.div
      className="bg-[#0d1117] border border-white/10 rounded-xl overflow-hidden shadow-2xl"
      initial={{ opacity: 0, x: 20 }}
      animate={show ? { opacity: 1, x: 0 } : {}}
      transition={{ duration: 0.6, delay: 0.3 }}
    >
      {/* Window controls */}
      <div className="flex items-center gap-2 px-4 py-3 bg-white/5 border-b border-white/10">
        <div className="w-3 h-3 rounded-full bg-red-500/80" />
        <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
        <div className="w-3 h-3 rounded-full bg-green-500/80" />
        <span className="ml-3 text-white/40 text-xs font-mono">example.py</span>
      </div>

      {/* Code content */}
      <pre className="p-4 lg:p-5 text-xs sm:text-sm font-mono leading-relaxed overflow-x-auto">
        <code>
          <span className="text-white/40"># Manager: Query SNMP devices</span>
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
  );
}

export default function LandingPage() {
  const [showContent, setShowContent] = useState(false);

  return (
    <div className="min-h-screen w-screen overflow-x-hidden overflow-y-auto relative bg-black">
      {/* Vignette overlay */}
      <div
        className="absolute inset-0 pointer-events-none z-10"
        style={{
          background:
            "radial-gradient(ellipse at center, transparent 0%, rgba(0,0,0,0.5) 60%, black 100%)",
        }}
      />

      {/* Main content - split layout */}
      <div className="relative min-h-screen flex flex-col-reverse lg:flex-row items-center justify-center z-20 px-6 lg:px-12 gap-6 lg:gap-10 py-12 lg:py-8">
        {/* Left side - Code snippet */}
        <div className="w-full max-w-sm sm:max-w-md lg:max-w-none lg:w-[460px] shrink-0">
          <CodeSnippet show={showContent} />
        </div>

        {/* Right side - Globe, branding, install */}
        <div className="flex flex-col items-center lg:items-start text-center lg:text-left space-y-4 lg:space-y-5 w-full max-w-sm sm:max-w-md lg:max-w-none lg:w-[360px] shrink-0">
          {/* Globe */}
          <div className="w-[180px] h-[180px] lg:w-[200px] lg:h-[200px]">
            <Globe />
          </div>

          {/* Logo */}
          <Logo onAnimationComplete={() => setShowContent(true)} />

          {/* Tagline */}
          <motion.p
            className="text-white/70 text-sm lg:text-base max-w-[320px] lg:max-w-none"
            initial={{ opacity: 0, y: 10 }}
            animate={showContent ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.6 }}
          >
            High-performance SNMP toolkit for Python, powered by Rust.
            <br />
            <span className="text-white/50">
              127x faster encoding. Full SNMPv1/v2c/v3 support.
            </span>
          </motion.p>

          {/* Install command */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={showContent ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.6, delay: 0.1 }}
          >
            <InstallCommand />
          </motion.div>

          {/* CTAs */}
          <motion.div
            className="flex gap-6 pt-1"
            initial={{ opacity: 0, y: 10 }}
            animate={showContent ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.6, delay: 0.2 }}
          >
            <CTA href="/docs/introduction">Get Started</CTA>
            <CTA href="/docs/examples">Examples</CTA>
          </motion.div>
        </div>
      </div>

      {/* Copyright */}
      <motion.div
        className="absolute bottom-4 left-0 right-0 text-center text-xs text-white/30 z-20"
        initial={{ opacity: 0 }}
        animate={showContent ? { opacity: 1 } : {}}
        transition={{ duration: 0.6, delay: 0.4 }}
      >
        © 2026 SnmpKit. All rights reserved.
      </motion.div>
    </div>
  );
}
