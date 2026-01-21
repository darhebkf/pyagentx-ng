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
      width="280"
      height="60"
      viewBox="0 0 280 60"
      className="mx-auto"
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

export default function LandingPage() {
  const [showContent, setShowContent] = useState(false);

  return (
    <div className="h-screen w-screen overflow-hidden relative bg-black">
      {/* Vignette overlay */}
      <div
        className="absolute inset-0 pointer-events-none z-10"
        style={{
          background:
            "radial-gradient(ellipse at center, transparent 0%, rgba(0,0,0,0.5) 60%, black 100%)",
        }}
      />

      {/* Main content - stacked vertically */}
      <div className="absolute inset-0 flex flex-col items-center justify-center z-20">
        {/* Globe above text */}
        <div className="w-[360px] h-[360px]">
          <Globe />
        </div>

        {/* Text content below globe */}
        <div className="text-center space-y-4 mt-4">
          <Logo onAnimationComplete={() => setShowContent(true)} />

          <motion.p
            className="text-white/70 text-base max-w-[280px] sm:max-w-none mx-auto"
            initial={{ opacity: 0, y: 10 }}
            animate={showContent ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.6 }}
          >
            High-performance SNMP toolkit with Python powered by Rust
          </motion.p>

          <motion.div
            className="flex gap-8 justify-center pt-2"
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
