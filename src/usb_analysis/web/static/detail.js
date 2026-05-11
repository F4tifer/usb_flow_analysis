export class FlowDetailPanel {
  constructor() {
    this.out = document.getElementById("flowDetailOut");
    this.causal = document.getElementById("flowCausalList");
    this.baseQueryProvider = null;
    this.onJumpToSeq = null;
    // Localisation hook — host app can override with a function returning
    // labels. Defaults to English so the module works standalone.
    this.labels = {
      loading: "Loading context...",
      error: "Could not load context.",
      empty: "No causal candidates.",
    };
    // Localise canonical-EN event content. Identity by default.
    this.contentLocalizer = (s) => s;
    // Generational guard — rapid event selection (arrow keys, click-storm)
    // used to race the async context fetch and overwrite the panel with stale
    // data from a previous selection. Each call bumps `_gen`; results that
    // come back with a stale gen are silently dropped.
    this._gen = 0;
  }

  setBaseQueryProvider(fn) {
    this.baseQueryProvider = fn;
  }

  async showEvent(event) {
    const myGen = ++this._gen;
    this.out.textContent = JSON.stringify(event, null, 2);
    this.causal.textContent = this.labels.loading;
    if (!this.baseQueryProvider) return;
    const q = this.baseQueryProvider();
    let res;
    try {
      res = await fetch(`/api/flow/context/${event.seq}${q}&before=8&after=4`);
    } catch {
      if (myGen !== this._gen) return;
      this.causal.textContent = this.labels.error;
      return;
    }
    if (myGen !== this._gen) return;
    if (!res.ok) {
      this.causal.textContent = this.labels.error;
      return;
    }
    const data = await res.json();
    if (myGen !== this._gen) return;
    const rows = data.causal_window || [];
    if (!rows.length) {
      this.causal.textContent = this.labels.empty;
      return;
    }
    this.causal.innerHTML = "";
    for (const e of rows) {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "causal-item";
      row.textContent = `#${e.seq} ${e.event_class} ${this.contentLocalizer(e.content || "")}`;
      row.onclick = () => this.onJumpToSeq && this.onJumpToSeq(e.seq);
      this.causal.append(row);
    }
  }
}
