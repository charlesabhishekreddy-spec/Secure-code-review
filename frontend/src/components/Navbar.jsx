import { NavLink } from "react-router-dom";

const links = [
  { label: "Home", to: "/" },
  { label: "Scanner", to: "/scanner" },
  { label: "Results", to: "/results" },
  { label: "History", to: "/history" }
];

export function Navbar() {
  return (
    <header className="glass-panel sticky top-4 z-20 flex items-center justify-between px-5 py-4 shadow-glow">
      <NavLink to="/" className="flex items-center gap-3">
        <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-mint to-cyan-300 text-base font-black text-slate-950">
          CS
        </div>
        <div>
          <p className="text-lg font-semibold text-white">CodeSentinel</p>
          <p className="text-xs uppercase tracking-[0.22em] text-slate-400">Secure Code Review</p>
        </div>
      </NavLink>
      <nav className="flex items-center gap-2">
        {links.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            className={({ isActive }) =>
              `rounded-2xl px-4 py-2 text-sm font-medium transition ${
                isActive ? "bg-white/10 text-white" : "text-slate-300 hover:bg-white/5 hover:text-white"
              }`
            }
          >
            {link.label}
          </NavLink>
        ))}
      </nav>
    </header>
  );
}
