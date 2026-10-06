export default function Home() {
  return (
    <main className="min-h-screen px-6 py-16">
      <div className="mx-auto max-w-5xl">
        <p className="text-sm font-medium uppercase tracking-[0.2em] text-zinc-400">
          IntentGuard / AgentFirewall
        </p>
        <h1 className="mt-4 text-5xl font-semibold tracking-tight">
          Runtime security for tool-using AI agents.
        </h1>
        <p className="mt-6 max-w-2xl text-lg leading-8 text-zinc-400">
          The gateway is the enforcement boundary. Task scope, tool capability,
          provenance and policy determine whether a protected action executes.
        </p>
        <div className="mt-10 grid gap-4 sm:grid-cols-3">
          {[
            ["Gateway", "Protected tool boundary"],
            ["Policy", "Deterministic authorization"],
            ["Audit", "Traceable security decisions"]
          ].map(([title, text]) => (
            <section key={title} className="rounded-2xl border border-zinc-800 p-5">
              <h2 className="font-medium">{title}</h2>
              <p className="mt-2 text-sm text-zinc-400">{text}</p>
            </section>
          ))}
        </div>
      </div>
    </main>
  );
}
