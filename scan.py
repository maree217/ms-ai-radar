#!/usr/bin/env python3
"""
MS-AI-Radar scanner — discovers the *latest* Microsoft AI / agent solutions on GitHub
and emits catalogue.json. Designed to run locally or in GitHub Actions (weekly cron).

Auth: uses $GITHUB_TOKEN; falls back to `gh auth token` for local runs.
Scope: official Microsoft orgs + high-star community repos tagged with MS/Azure-AI topics.
Freshness: drops archived repos and anything not pushed within FRESH_MONTHS; flags
           superseded/deprecated repos; ranks by stars + creation recency.
"""
import os, sys, time, json, subprocess, datetime, urllib.request, urllib.parse, urllib.error

API = "https://api.github.com/search/repositories"

MS_ORGS = ["microsoft", "Azure-Samples", "Azure", "microsoft-foundry", "dotnet"]

# Official-ish topics Microsoft uses to tag current AI/agent work (also catches community)
TOPICS = [
    "ai-azd-templates", "azure-ai-foundry", "azureaifoundry", "ai-agents", "agentic-ai",
    "model-context-protocol", "mcp", "copilot-studio", "semantic-kernel", "agent-skills",
    "microsoft-iq", "foundry-local", "azure-openai", "microsoft-foundry",
]
KEYWORDS = [
    "agent", "foundry", "ai agent", "agent framework", "mcp", "copilot",
    "rag", "solution accelerator", "agentic", "autonomous agent",
]

COMMUNITY_MIN_STARS = 150         # quality bar for non-Microsoft repos (tune for breadth)
# Community repos qualify ONLY if the author tagged them with one of these intentional
# Microsoft-stack topics. (We deliberately exclude generic topics like `mcp`/`ai-agents`
# and the noisy `azure-openai`, which multi-provider tools tag just for Azure support.)
COMMUNITY_TOPICS = {
    "azure-ai-foundry", "azureaifoundry", "microsoft-foundry", "foundry-local",
    "copilot-studio", "semantic-kernel", "microsoft-iq", "microsoft-365-copilot",
    "ai-azd-templates", "power-platform", "dataverse",
}
FRESH_MONTHS = 18                 # exclude repos not pushed within this window
THIS_YEAR = str(datetime.date.today().year)

DENY_NAMES = {"WALinuxAgent", "AgentBaker", "iot-hub-device-update", "azure-functions-host"}
DENY_DESC = ("kubernetes node", "vm agent", "linux vm", "node bootstrap", "aks node",
             "guest agent", "cluster autoscaler", "device update")
INCL = ("agent", "copilot", "foundry", "genai", "llm", "rag", "mcp", "gpt", "semantic kernel",
        "prompt", "model context", "autogen", "chatbot", "openai", "intelligen", "skill",
        "autonomous", "multi-agent", " ai ", "ai-", "-ai", "azure ai", "language model")
SUPERSEDED = ("deprecated", "no longer maintain", "moved to", "superseded", "use instead",
              "maintenance mode", "archived in favor", "has moved", "now moved", "retired")


def token():
    t = os.environ.get("GITHUB_TOKEN")
    if t:
        return t
    try:
        return subprocess.check_output(["gh", "auth", "token"]).decode().strip()
    except Exception:
        print("ERROR: set $GITHUB_TOKEN or install/auth `gh`.", file=sys.stderr)
        sys.exit(1)


TOKEN = token()


def search(q, pages=2):
    out = []
    for page in range(1, pages + 1):
        url = API + "?" + urllib.parse.urlencode(
            {"q": q, "sort": "stars", "order": "desc", "per_page": 100, "page": page})
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "ms-ai-radar"})
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req) as r:
                    items = json.load(r).get("items", [])
                out += items
                if len(items) < 100:
                    return out
                break
            except urllib.error.HTTPError as e:
                if e.code in (403, 429):          # secondary rate limit
                    time.sleep(20 * (attempt + 1))
                    continue
                print(f"HTTP {e.code} for: {q}", file=sys.stderr)
                return out
        time.sleep(2.2)
    return out


def months_since(iso):
    d = datetime.date.fromisoformat(iso[:10])
    return (datetime.date.today() - d).days / 30.0


def relevant(r):
    name = r["name"]
    if name in DENY_NAMES:
        return False
    blob = ((r.get("description") or "") + " " + name).lower()
    if any(x in blob for x in DENY_DESC):
        return False
    return any(x in blob for x in INCL) or bool(set(r.get("topics", [])) & set(TOPICS))


def categorise(r):
    name = r["name"].lower()
    desc = (r.get("description") or "").lower()
    topics = set(r.get("topics", []))
    b = name + " " + desc
    def has(*ks): return any(k in b for k in ks)
    def tp(*ks): return bool(topics & set(ks))

    if has("beginners", "curriculum", "course", "workshop", "tutorial", "lessons",
           "learning journey", "livestream", "bootcamp", "hands-on lab", "model mondays"):
        return "Learning & curricula"
    if "solution-accelerator" in name or "solution accelerator" in desc:
        return "Solution Accelerators"
    if has("mcp", "model context protocol") or tp("mcp", "model-context-protocol"):
        return "MCP servers & tools"
    if has("work-iq", "work iq", "foundry-iq", "fabric-iq", "microsoft iq", "iq series", "iq-series") \
            or tp("microsoft-iq", "foundry-iq", "fabric-iq", "work-iq"):
        return "Microsoft IQ & data grounding"
    if has("agent365", "agent 365", "governance", "windows-365", "windows 365",
           "zero-trust", "zero trust", "entra", "identity and access") or tp("ai-safety"):
        return "Agent 365 · Windows · Governance"
    if has("skill", "plugin", "agents.md") or tp("agent-skills"):
        return "Skills & agent plugins"
    if has("computer use", "computer-use", "screen pars", "gui agent", "browser agent",
           "os agent", "desktop agent", "omniparser", "use agent", "operating system"):
        return "Computer-use & OS agents"
    if has("rag", "retrieval-augmented", "retrieval augmented", " retrieval", "vector search",
           "embeddings", "knowledge base", "knowledge graph", "graphrag", "semantic search",
           "knowledge mining", "ai search"):
        return "RAG, search & knowledge"
    if has("fine-tun", "finetune", "distill", "quantiz", "foundation model", "model training",
           "trainer", "reinforcement", "quant investment", "pretrain", "run llm", "run any model",
           "on-device", "local llm", "inference") or tp("foundry-local", "on-device-inference", "local-ai"):
        return "Models, training & optimization"
    if has("sandbox", "simulation", "arena", "benchmark", "research platform",
           "experimentation", "environment for", " gym"):
        return "Research & environments"
    if has("command-line", " cli", "cli ", "terminal", "vscode", "vs code extension",
           "devtools", "package manager", "toolkit", "translator", "debugger"):
        return "Dev tooling & CLI"
    if has("agent-framework", "agent framework", " sdk", "-sdk", "framework", "orchestrat",
           "runtime", "build ai agents", "building ai agents", "multi-agent", "multi agent") \
            and not has("sample", "demo"):
        return "Frameworks & SDKs"
    if has("sample", "demo", "quickstart", "get-started", "getting started", "baseline",
           "playbook", "examples", "reference architecture", "reference implementation"):
        return "Samples & quickstarts"
    if has("copilot", "chatbot", "chat with", "build your own", "assistant",
           "call center", "voice agent", "creative writer"):
        return "Apps & copilots"
    return "Other agentic tools"


def tier(r):
    s = r["stargazers_count"]
    if s >= 1000:
        return "flagship"
    if s >= 100:
        return "established"
    if r["created_at"][:4] == THIS_YEAR:
        return "new"
    return "emerging"


def freshness(r):
    m = months_since(r["pushed_at"])
    if m <= 3:
        return "fresh"
    if m <= 12:
        return "active"
    return "stale"


def load_overrides():
    p = os.path.join(os.path.dirname(__file__), "overrides.json")
    if os.path.exists(p):
        try:
            return json.load(open(p))
        except Exception as e:
            print(f"WARN: overrides.json unreadable: {e}", file=sys.stderr)
    return {}


def main():
    overrides = load_overrides()
    raw = {}
    # Microsoft orgs: keyword sweeps (no star floor)
    for org in MS_ORGS:
        for kw in KEYWORDS:
            for r in search(f'{kw} org:{org} archived:false', pages=1):
                raw[r["full_name"]] = r
            time.sleep(2.2)
    # Topics across all owners (community + MS), with star floor for quality
    for t in TOPICS:
        for r in search(f'topic:{t} archived:false stars:>={COMMUNITY_MIN_STARS}', pages=2):
            raw.setdefault(r["full_name"], r)
        time.sleep(2.2)

    catalogue = []
    for r in raw.values():
        if r.get("archived"):
            continue
        if months_since(r["pushed_at"]) > FRESH_MONTHS:
            continue
        if not relevant(r):
            continue
        owner = r["full_name"].split("/")[0]
        is_ms = owner in MS_ORGS
        if not is_ms:
            if r["stargazers_count"] < COMMUNITY_MIN_STARS:
                continue
            if not (set(r.get("topics", [])) & COMMUNITY_TOPICS):
                continue
        desc = r.get("description") or ""
        rec = {
            "repo": r["full_name"], "owner": owner,
            "source": "microsoft" if is_ms else "community",
            "stars": r["stargazers_count"], "desc": desc,
            "lang": r.get("language"), "pushed": r["pushed_at"][:10],
            "created": r["created_at"][:10], "topics": r.get("topics", [])[:8],
            "url": r["html_url"], "homepage": r.get("homepage") or "",
            "category": categorise(r), "tier": tier(r), "fresh": freshness(r),
            "superseded": any(s in desc.lower() for s in SUPERSEDED),
            "status": "", "note": "", "pin": False,
        }
        # Curated overrides: keyed by "owner/name" or bare "name"
        ov = overrides.get(rec["repo"]) or overrides.get(r["name"]) or {}
        if ov.get("hide"):
            continue
        if ov.get("category"):
            rec["category"] = ov["category"]
        if ov.get("status"):
            rec["status"] = ov["status"]
        if ov.get("note"):
            rec["note"] = ov["note"]
        if ov.get("status") in ("maintenance", "deprecated", "moved"):
            rec["superseded"] = True
        rec["pin"] = bool(ov.get("pin"))
        catalogue.append(rec)

    # pinned first, then by stars
    catalogue.sort(key=lambda x: (not x["pin"], -x["stars"]))
    payload = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "count": len(catalogue),
        "ms_orgs": MS_ORGS,
        "community_min_stars": COMMUNITY_MIN_STARS,
        "fresh_months": FRESH_MONTHS,
        "repos": catalogue,
    }
    with open(os.path.join(os.path.dirname(__file__), "catalogue.json"), "w") as f:
        json.dump(payload, f, indent=1)

    from collections import Counter
    print(f"catalogue.json: {len(catalogue)} repos "
          f"({sum(1 for c in catalogue if c['source']=='microsoft')} MS, "
          f"{sum(1 for c in catalogue if c['source']=='community')} community)")
    for cat, n in Counter(c["category"] for c in catalogue).most_common():
        print(f"  {n:4}  {cat}")


if __name__ == "__main__":
    main()
