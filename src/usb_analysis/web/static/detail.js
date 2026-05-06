export class FlowDetailPanel {
  constructor() {
    this.out = document.getElementById("flowDetailOut");
    this.causal = document.getElementById("flowCausalList");
    this.baseQueryProvider = null;
    this.onJumpToSeq = null;
  }

  setBaseQueryProvider(fn) {
    this.baseQueryProvider = fn;
  }

  async showEvent(event) {
    this.out.textContent = JSON.stringify(event, null, 2);
    this.causal.textContent = "Načítám kontext...";
    if (!this.baseQueryProvider) return;
    const q = this.baseQueryProvider();
    const res = await fetch(`/api/flow/context/${event.seq}${q}&before=8&after=4`);
    if (!res.ok) {
      this.causal.textContent = "Kontext se nepodařilo načíst.";
      return;
    }
    const data = await res.json();
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
