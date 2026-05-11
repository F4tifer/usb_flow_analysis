export class FlowDetailPanel {
  constructor() {
    this.out = document.getElementById("flowDetailOut");
    this.causal = document.getElementById("flowCausalList");
    this.baseQueryProvider = null;
    this.onJumpToSeq = null;
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
    this.causal.textContent = "Načítám kontext...";
    if (!this.baseQueryProvider) return;
    const q = this.baseQueryProvider();
    let res;
    try {
      res = await fetch(`/api/flow/context/${event.seq}${q}&before=8&after=4`);
    } catch {
      if (myGen !== this._gen) return;
      this.causal.textContent = "Kontext se nepodařilo načíst.";
      return;
    }
    if (myGen !== this._gen) return;            // user moved on
    if (!res.ok) {
      this.causal.textContent = "Kontext se nepodařilo načíst.";
      return;
    }
    const data = await res.json();
    if (myGen !== this._gen) return;            // user moved on while parsing
    const rows = data.causal_window || [];
    if (!rows.length) {
      this.causal.textContent = "Bez kauzálních kandidátů.";
      return;
    }
    this.causal.innerHTML = "";
    for (const e of rows) {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "causal-item";
      row.textContent = `#${e.seq} ${e.event_class} ${e.content}`;
      row.onclick = () => this.onJumpToSeq && this.onJumpToSeq(e.seq);
      this.causal.append(row);
    }
  }
}
